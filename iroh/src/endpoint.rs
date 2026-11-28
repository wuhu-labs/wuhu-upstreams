//! Endpoints and connections.

use std::{
    ffi::{c_char, c_void},
    net::{IpAddr, SocketAddr},
    ptr,
    sync::{Arc, Mutex, Weak},
};

use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    Watcher,
    endpoint::{Connection, ConnectionError, VarInt, presets},
};
use tokio::task::AbortHandle;

use crate::op::{Outcome, RunOnce, fill, guard, handle, key, spawn, text, wi_callback};
use crate::stream::{RecvHandle, SendHandle};
use crate::watch::wi_watch;

#[allow(non_camel_case_types)]
pub struct wi_endpoint {
    endpoint: Endpoint,
    relays: RelayMap,
    alpn: Vec<u8>,
    close: RunOnce<()>,
    connections: Arc<Mutex<Connections>>,
    failover: AbortHandle,
}

impl Drop for wi_endpoint {
    fn drop(&mut self) {
        self.failover.abort();
    }
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

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_relay_entry {
    url: *const c_char,
    auth_token: *const c_char,
}

fn relay_config(url: RelayUrl, auth_token: Option<String>) -> Arc<RelayConfig> {
    let mut config = RelayConfig::from(url);
    config.quic = None;
    config.auth_token = auth_token;
    Arc::new(config)
}

/// iroh moves its home relay only after a net report, which runs every 20 to 26 s; a relay map
/// change runs one at once, so each failure of the home relay's connection re-inserts its entry.
async fn fail_over(endpoint: Endpoint, relays: RelayMap) {
    let closing = endpoint.clone();
    let mut statuses = endpoint
        .home_relay_status()
        .stream_updates_only()
        .take_until(async move { closing.closed().await })
        .boxed();
    while let Some(statuses) = statuses.next().await {
        let Some(home) = statuses.first() else {
            continue;
        };
        if home.is_connected() || home.last_error().is_none() {
            continue;
        }
        if let Some(config) = relays.get(home.url()) {
            endpoint.insert_relay(home.url().clone(), config).await;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_bind(
    secret_key: *const u8,
    relays: *const wi_relay_entry,
    relay_count: usize,
    relay_only: bool,
    alpn: *const u8,
    alpn_len: usize,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let secret = SecretKey::from_bytes(&unsafe { key(secret_key) });
    let entries: Vec<_> = if relay_count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(relays, relay_count) }
            .iter()
            .map(|entry| unsafe { (text(entry.url), text(entry.auth_token)) })
            .collect()
    };
    let alpn = if alpn_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(alpn, alpn_len) }.to_vec()
    };
    spawn(callback, context, async move {
        let relays = RelayMap::empty();
        for (url, auth_token) in entries {
            match relay_url(url) {
                Ok(url) => {
                    relays.insert(url.clone(), relay_config(url, auth_token));
                }
                Err(e) => return Outcome::Error(e),
            }
        }
        if relays.is_empty() {
            return Outcome::Error("no relay".into());
        }
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Custom(relays.clone()));
        if relay_only {
            builder = builder.clear_ip_transports();
        }
        match builder.bind().await {
            Ok(endpoint) => {
                let failover =
                    tokio::spawn(fail_over(endpoint.clone(), relays.clone())).abort_handle();
                Outcome::Handle(handle(wi_endpoint {
                    endpoint,
                    relays,
                    alpn,
                    close: RunOnce::new(),
                    connections: Default::default(),
                    failover,
                }))
            }
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_set_auth_token(
    endpoint: *const wi_endpoint,
    relay_url_text: *const c_char,
    auth_token: *const c_char,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let relays = this.relays.clone();
    let relay = relay_url(unsafe { text(relay_url_text) });
    let auth_token = unsafe { text(auth_token) };
    spawn(callback, context, async move {
        let relay = match relay {
            Ok(relay) => relay,
            Err(e) => return Outcome::Error(e),
        };
        if !relays.contains(&relay) {
            return Outcome::Error(format!("relay URL {relay} is not in the endpoint's map"));
        }
        endpoint
            .insert_relay(relay.clone(), relay_config(relay, auth_token))
            .await;
        Outcome::Ok
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
    relay_url_text: *const c_char,
    addresses: *const *const c_char,
    address_count: usize,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*endpoint };
    let endpoint = this.endpoint.clone();
    let alpn = this.alpn.clone();
    let connections = this.connections.clone();
    let peer = PublicKey::from_bytes(&unsafe { key(public_key) });
    let relay = unsafe { text(relay_url_text) }.map(|url| relay_url(Some(url)));
    let addresses: Vec<_> = if address_count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(addresses, address_count) }
            .iter()
            .map(|address| unsafe { text(*address) }.unwrap_or_default())
            .collect()
    };
    spawn(callback, context, async move {
        let peer = match peer {
            Ok(peer) => peer,
            Err(e) => return Outcome::error(e),
        };
        let mut address = EndpointAddr::new(peer);
        match relay {
            Some(Ok(relay)) => address = address.with_relay_url(relay),
            Some(Err(e)) => return Outcome::Error(e),
            None => {}
        }
        for text in addresses {
            match text.parse::<SocketAddr>() {
                Ok(ip) => address = address.with_ip_addr(ip),
                Err(e) => return Outcome::Error(format!("address {text}: {e}")),
            }
        }
        if address.is_empty() {
            return Outcome::Error("neither a relay URL nor an address to dial".into());
        }
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
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, dead_code)]
pub enum wi_relay_kind {
    WI_RELAY_HOME = 0,
    WI_RELAY_REACHABLE = 1,
    WI_RELAY_UNREACHABLE = 2,
    WI_RELAY_UNPROBED = 3,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_relay_state {
    url: [c_char; 256],
    kind: wi_relay_kind,
    connected: bool,
    last_error: [c_char; 256],
    latency_micros: u64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_relays(
    endpoint: *const wi_endpoint,
    out: *mut wi_relay_state,
    capacity: usize,
) -> usize {
    let this = unsafe { &*endpoint };
    guard(0, || {
        let urls: Vec<RelayUrl> = this.relays.urls();
        let home = this.endpoint.home_relay_status().get().into_iter().next();
        let report = this.endpoint.net_report().get();
        let out = if capacity == 0 {
            &mut [][..]
        } else {
            unsafe { std::slice::from_raw_parts_mut(out, capacity) }
        };
        for (url, slot) in urls.iter().zip(out.iter_mut()) {
            fill(&mut slot.url, url.as_str());
            slot.connected = false;
            fill(&mut slot.last_error, "");
            slot.latency_micros = 0;
            slot.kind = match (&home, &report) {
                (Some(home), _) if home.url() == url => {
                    slot.connected = home.is_connected();
                    let error = home
                        .last_error()
                        .map(|e| format!("{e:#}"))
                        .unwrap_or_default();
                    fill(&mut slot.last_error, &error);
                    wi_relay_kind::WI_RELAY_HOME
                }
                (_, None) => wi_relay_kind::WI_RELAY_UNPROBED,
                (_, Some(report)) => match report
                    .relay_latency
                    .iter()
                    .filter(|(_, probed, _)| *probed == url)
                    .map(|(_, _, latency)| latency)
                    .min()
                {
                    Some(latency) => {
                        slot.latency_micros = (latency.as_micros() as u64).max(1);
                        wi_relay_kind::WI_RELAY_REACHABLE
                    }
                    None => wi_relay_kind::WI_RELAY_UNREACHABLE,
                },
            };
        }
        urls.len()
    })
}

fn advertised(address: &SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified(),
        IpAddr::V6(ip) => ip.segments()[0] & 0xe000 == 0x2000,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_direct_addresses(
    endpoint: *const wi_endpoint,
    out: *mut c_char,
    capacity: usize,
) -> usize {
    let this = unsafe { &*endpoint };
    guard(0, || {
        let mut addresses: Vec<SocketAddr> = this
            .endpoint
            .addr()
            .ip_addrs()
            .copied()
            .filter(advertised)
            .collect();
        addresses.sort();
        let text: String = addresses.iter().map(|a| format!("{a}\n")).collect();
        if text.len() < capacity {
            unsafe {
                ptr::copy_nonoverlapping(text.as_ptr() as *const c_char, out, text.len());
                *out.add(text.len()) = 0;
            }
        }
        text.len()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_watch(endpoint: *const wi_endpoint) -> *mut wi_watch {
    let endpoint = unsafe { &*endpoint }.endpoint.clone();
    guard(ptr::null_mut(), || {
        let closing = endpoint.clone();
        let changes = futures_util::stream::select_all([
            endpoint
                .home_relay_status()
                .stream_updates_only()
                .map(|_| ())
                .boxed(),
            endpoint
                .net_report()
                .stream_updates_only()
                .map(|_| ())
                .boxed(),
            endpoint
                .watch_addr()
                .stream_updates_only()
                .map(|_| ())
                .boxed(),
        ])
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
pub unsafe extern "C" fn wi_connection_path_watch(
    connection: *const wi_connection,
) -> *mut wi_watch {
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
    guard((), || {
        closer.close(VarInt::from_u64(code).unwrap_or(VarInt::MAX))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_free(connection: *mut wi_connection) {
    guard((), || drop(unsafe { Box::from_raw(connection) }))
}

#[doc(hidden)]
pub unsafe fn net_reports(endpoint: *const c_void) -> u64 {
    let this = unsafe { &*(endpoint as *const wi_endpoint) };
    this.endpoint.metrics().net_report.reports.get()
}
