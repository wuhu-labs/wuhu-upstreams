//! Endpoints and connections.

use std::{
    ffi::{c_char, c_void},
    ptr,
    sync::{Arc, Mutex, Weak},
};

use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    Watcher,
    endpoint::{Connection, ConnectionError, VarInt, presets},
};
use futures_util::StreamExt;

use crate::op::{Outcome, RunOnce, fill, guard, handle, key, spawn, text, wi_callback};
use crate::stream::{RecvHandle, SendHandle};
use crate::watch::wi_watch;

#[allow(non_camel_case_types)]
pub struct wi_endpoint {
    endpoint: Endpoint,
    relay: RelayUrl,
    alpn: Vec<u8>,
    close: RunOnce<()>,
    connections: Arc<Mutex<Connections>>,
}

/// The endpoint's connections, so that its close goes through each one's `Closer`.
#[derive(Default)]
struct Connections {
    closed: bool,
    live: Vec<Weak<Closer>>,
}

impl Connections {
    fn adopt(connections: &Mutex<Connections>, connection: Connection) -> wi_connection {
        let closer = Arc::new(Closer {
            connection,
            won: Mutex::new(None),
        });
        let mut connections = connections.lock().unwrap_or_else(|e| e.into_inner());
        if connections.closed {
            closer.close(VarInt::from_u32(0));
        } else {
            connections.live.retain(|c| c.strong_count() > 0);
            connections.live.push(Arc::downgrade(&closer));
        }
        wi_connection(closer)
    }
}

/// iroh reports every local close only as "locally closed". Ours and the endpoint's all go through
/// `won`, which keeps the code of the one that reached noq first: the one the peer saw.
struct Closer {
    connection: Connection,
    won: Mutex<Option<u64>>,
}

impl Closer {
    fn close(&self, code: VarInt) {
        let mut won = self.won.lock().unwrap_or_else(|e| e.into_inner());
        if won.is_none() && self.connection.close_reason().is_none() {
            *won = Some(code.into_inner());
        }
        self.connection.close(code, b"");
    }
}

#[allow(non_camel_case_types)]
pub struct wi_connection(Arc<Closer>);

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
    let alpn = if alpn_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(alpn, alpn_len) }.to_vec()
    };
    spawn(callback, context, async move {
        let relay = match relay {
            Ok(relay) => relay,
            Err(e) => return Outcome::Error(e),
        };
        let mut config = RelayConfig::from(relay.clone());
        config.quic = None;
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Custom(RelayMap::from(config)));
        if relay_only {
            builder = builder.clear_ip_transports();
        }
        match builder.bind().await {
            Ok(endpoint) => Outcome::Handle(handle(wi_endpoint {
                endpoint,
                relay,
                alpn,
                close: RunOnce::new(),
                connections: Default::default(),
            })),
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_secret_key_public(secret_key: *const u8, out: *mut u8) {
    let secret = SecretKey::from_bytes(&unsafe { key(secret_key) });
    guard((), || {
        let bytes = *secret.public().as_bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
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
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let alpn = this.alpn.clone();
    let relay = this.relay.clone();
    let connections = this.connections.clone();
    let peer = PublicKey::from_bytes(&unsafe { key(public_key) });
    spawn(callback, context, async move {
        let peer = match peer {
            Ok(peer) => peer,
            Err(e) => return Outcome::error(e),
        };
        let address = EndpointAddr::new(peer).with_relay_url(relay);
        match endpoint.connect(address, &alpn).await {
            Ok(connection) => {
                let remote = *connection.remote_id().as_bytes();
                Outcome::Keyed(handle(Connections::adopt(&connections, connection)), remote)
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
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let connections = this.connections.clone();
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
                    return Outcome::Keyed(
                        handle(Connections::adopt(&connections, connection)),
                        remote,
                    );
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
pub unsafe extern "C" fn wi_endpoint_relay_watch(endpoint: *const wi_endpoint) -> *mut wi_watch {
    let endpoint = unsafe { &*endpoint }.endpoint.clone();
    guard(ptr::null_mut(), || {
        let closing = endpoint.clone();
        let changes = endpoint
            .home_relay_status()
            .stream_updates_only()
            .map(|_| ())
            .take_until(async move { closing.closed().await })
            .boxed();
        handle(wi_watch::new(changes)) as *mut wi_watch
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_close(
    endpoint: *const wi_endpoint,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let connections = this.connections.clone();
    let closing = this.close.run((), || async move {
        let live = {
            let mut connections = connections.lock().unwrap_or_else(|e| e.into_inner());
            connections.closed = true;
            std::mem::take(&mut connections.live)
        };
        for closer in live.iter().filter_map(Weak::upgrade) {
            closer.close(VarInt::from_u32(0));
        }
        endpoint.close().await
    });
    spawn(callback, context, async move {
        closing.await;
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
        let bytes = *connection.0.connection.remote_id().as_bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_open(
    connection: *const wi_connection,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let connection = unsafe { &*connection }.0.connection.clone();
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
    let connection = unsafe { &*connection }.0.connection.clone();
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
        let paths = connection.0.connection.paths();
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
pub unsafe extern "C" fn wi_connection_path_watch(connection: *const wi_connection) -> *mut wi_watch {
    let connection = &unsafe { &*connection }.0.connection;
    guard(ptr::null_mut(), || {
        let closing = connection.weak_handle();
        let changes = connection
            .path_events()
            .map(|_| ())
            .take_until(async move { closing.closed().await })
            .boxed();
        handle(wi_watch::new(changes)) as *mut wi_watch
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_closed(
    connection: *const wi_connection,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let closer = unsafe { &*connection }.0.clone();
    spawn(callback, context, async move {
        let error = closer.connection.closed().await;
        let won = *closer.won.lock().unwrap_or_else(|e| e.into_inner());
        let (code, reason) = match error {
            ConnectionError::LocallyClosed => (won.unwrap_or(0), String::new()),
            other => closed_reason(&other),
        };
        Outcome::ClosedWith(code, reason)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_close(connection: *const wi_connection, code: u64) {
    let closer = &unsafe { &*connection }.0;
    guard((), || closer.close(VarInt::from_u64(code).unwrap_or(VarInt::MAX)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_free(connection: *mut wi_connection) {
    guard((), || drop(unsafe { Box::from_raw(connection) }))
}
