//! Endpoints and connections.

use std::{ffi::c_char, ffi::c_void, sync::Arc};

use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    Watcher,
    endpoint::{Connection, ConnectionError, PathEventStream, RelayStatus, presets},
};
use futures_util::{StreamExt, stream::BoxStream};
use tokio::sync::Mutex;

use crate::op::{Outcome, fill, guard, handle, key, spawn, text, wi_callback};
use crate::stream::{RecvHandle, SendHandle};

#[allow(non_camel_case_types)]
pub struct wi_endpoint {
    endpoint: Endpoint,
    alpn: Vec<u8>,
    relay_changes: Arc<Mutex<BoxStream<'static, Vec<RelayStatus>>>>,
}

#[allow(non_camel_case_types)]
pub struct wi_connection {
    connection: Connection,
    path_events: Arc<Mutex<PathEventStream>>,
}

impl wi_connection {
    fn new(connection: Connection) -> Self {
        let path_events = Arc::new(Mutex::new(connection.path_events()));
        wi_connection {
            connection,
            path_events,
        }
    }
}

fn relay_url(text: Option<String>) -> Result<RelayUrl, String> {
    let text = text.ok_or("no relay URL")?;
    text.parse::<RelayUrl>()
        .map_err(|e| format!("relay URL {text}: {e}"))
}

fn closed_reason(error: &ConnectionError) -> (u64, String) {
    match error {
        ConnectionError::ApplicationClosed(close) => (
            close.error_code.into_inner(),
            String::from_utf8_lossy(&close.reason).into_owned(),
        ),
        other => (0, other.to_string()),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_bind(
    secret_key: *const u8,
    relay_url_text: *const c_char,
    relay_only: bool,
    alpn: *const u8,
    alpn_len: usize,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let secret = SecretKey::from_bytes(&unsafe { key(secret_key) });
    let relay = relay_url(unsafe { text(relay_url_text) });
    let alpn = unsafe { std::slice::from_raw_parts(alpn, alpn_len) }.to_vec();
    spawn(callback, context, async move {
        let relay = match relay {
            Ok(relay) => relay,
            Err(e) => return Outcome::Error(e),
        };
        let mut config = RelayConfig::from(relay);
        config.quic = None;
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Custom(RelayMap::from(config)));
        if relay_only {
            builder = builder.clear_ip_transports();
        }
        match builder.bind().await {
            Ok(endpoint) => {
                let changes = endpoint.home_relay_status().stream_updates_only().boxed();
                Outcome::Handle(handle(wi_endpoint {
                    endpoint,
                    alpn,
                    relay_changes: Arc::new(Mutex::new(changes)),
                }))
            }
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_key(endpoint: *const wi_endpoint, out: *mut u8) {
    let endpoint = unsafe { &*endpoint };
    guard((), || {
        let bytes = endpoint.endpoint.id().as_bytes().to_owned();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_connect(
    endpoint: *const wi_endpoint,
    public_key: *const u8,
    relay_url_text: *const c_char,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let alpn = this.alpn.clone();
    let peer = PublicKey::from_bytes(&unsafe { key(public_key) });
    let relay = relay_url(unsafe { text(relay_url_text) });
    spawn(callback, context, async move {
        let peer = match peer {
            Ok(peer) => peer,
            Err(e) => return Outcome::error(e),
        };
        let relay = match relay {
            Ok(relay) => relay,
            Err(e) => return Outcome::Error(e),
        };
        let address = EndpointAddr::new(peer).with_relay_url(relay);
        match endpoint.connect(address, &alpn).await {
            Ok(connection) => {
                let remote = *connection.remote_id().as_bytes();
                Outcome::Keyed(handle(wi_connection::new(connection)), remote)
            }
            Err(e) if endpoint.is_closed() => Outcome::Closed(format!("{e:#}")),
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_accept(
    endpoint: *const wi_endpoint,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let endpoint = unsafe { &*endpoint }.endpoint.clone();
    spawn(callback, context, async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                return Outcome::Closed("endpoint closed".into());
            };
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(e) => {
                    tracing::debug!("incoming refused: {e:#}");
                    continue;
                }
            };
            match accepting.await {
                Ok(connection) => {
                    let remote = *connection.remote_id().as_bytes();
                    return Outcome::Keyed(handle(wi_connection::new(connection)), remote);
                }
                Err(e) => tracing::debug!("handshake failed: {e:#}"),
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_network_change(
    endpoint: *const wi_endpoint,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let endpoint = unsafe { &*endpoint }.endpoint.clone();
    spawn(callback, context, async move {
        endpoint.network_change().await;
        Outcome::Ok
    })
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_relay_state {
    connected: bool,
    url: [c_char; 256],
    last_error: [c_char; 256],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_relay_state(
    endpoint: *const wi_endpoint,
    out: *mut wi_relay_state,
) -> bool {
    let endpoint = unsafe { &*endpoint };
    let out = unsafe { &mut *out };
    guard(false, || {
        let statuses = endpoint.endpoint.home_relay_status().get();
        let Some(status) = statuses.first() else {
            return false;
        };
        out.connected = status.is_connected();
        fill(&mut out.url, status.url().as_str());
        let error = status
            .last_error()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        fill(&mut out.last_error, &error);
        true
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_relay_changed(
    endpoint: *const wi_endpoint,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let changes = this.relay_changes.clone();
    spawn(callback, context, async move {
        let mut changes = changes.lock().await;
        tokio::select! {
            changed = changes.next() => match changed {
                Some(_) => Outcome::Ok,
                None => Outcome::Closed("endpoint closed".into()),
            },
            _ = endpoint.closed() => Outcome::Closed("endpoint closed".into()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_close(
    endpoint: *const wi_endpoint,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let endpoint = unsafe { &*endpoint }.endpoint.clone();
    spawn(callback, context, async move {
        endpoint.close().await;
        Outcome::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_free(endpoint: *mut wi_endpoint) {
    guard((), || drop(unsafe { Box::from_raw(endpoint) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_peer(connection: *const wi_connection, out: *mut u8) {
    let connection = unsafe { &*connection };
    guard((), || {
        let bytes = *connection.connection.remote_id().as_bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_open(
    connection: *const wi_connection,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let connection = unsafe { &*connection }.connection.clone();
    spawn(callback, context, async move {
        match connection.open_bi().await {
            Ok((send, recv)) => {
                Outcome::Handles(handle(SendHandle::new(send)), handle(RecvHandle::new(recv)))
            }
            Err(e) => Outcome::Closed(closed_reason(&e).1),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_accept(
    connection: *const wi_connection,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let connection = unsafe { &*connection }.connection.clone();
    spawn(callback, context, async move {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                Outcome::Handles(handle(SendHandle::new(send)), handle(RecvHandle::new(recv)))
            }
            Err(e) => Outcome::Closed(closed_reason(&e).1),
        }
    })
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_path {
    relay: bool,
    rtt_micros: u64,
    remote: [c_char; 256],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_path(
    connection: *const wi_connection,
    out: *mut wi_path,
) -> bool {
    let connection = unsafe { &*connection };
    let out = unsafe { &mut *out };
    guard(false, || {
        let paths = connection.connection.paths();
        let Some(path) = paths
            .iter()
            .find(|p| p.is_selected())
            .or_else(|| paths.iter().next())
        else {
            return false;
        };
        out.relay = path.is_relay();
        out.rtt_micros = path.rtt().as_micros() as u64;
        let remote = match path.remote_addr() {
            iroh::TransportAddr::Relay(url) => url.to_string(),
            iroh::TransportAddr::Ip(address) => address.to_string(),
            other => format!("{other:?}"),
        };
        fill(&mut out.remote, &remote);
        true
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_path_changed(
    connection: *const wi_connection,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let events = unsafe { &*connection }.path_events.clone();
    spawn(callback, context, async move {
        match events.lock().await.next().await {
            Some(_) => Outcome::Ok,
            None => Outcome::Closed("connection closed".into()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_closed(
    connection: *const wi_connection,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let connection = unsafe { &*connection }.connection.clone();
    spawn(callback, context, async move {
        let (code, reason) = closed_reason(&connection.closed().await);
        Outcome::ClosedWith(code, reason)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_close(connection: *const wi_connection, code: u64) {
    let connection = unsafe { &*connection };
    guard((), || {
        let code = iroh::endpoint::VarInt::from_u64(code).unwrap_or(iroh::endpoint::VarInt::MAX);
        connection.connection.close(code, b"");
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_free(connection: *mut wi_connection) {
    guard((), || drop(unsafe { Box::from_raw(connection) }))
}
