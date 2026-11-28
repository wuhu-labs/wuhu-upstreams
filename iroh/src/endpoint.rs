//! Endpoints and connections.

use std::{
    ffi::{CString, c_char, c_void},
    net::{IpAddr, SocketAddr},
    ptr,
    sync::{Arc, Mutex, Weak},
};

use crate::op::{Outcome, RunOnce, guard, handle, key, runtime, spawn, text, wi_callback};
use crate::stream::{RecvHandle, SendHandle};
use crate::watch::wi_watch;
use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    Watcher,
    endpoint::{Connection, ConnectionError, PortmapperConfig, VarInt, presets},
};

#[allow(non_camel_case_types)]
pub struct wi_endpoint {
    endpoint: Endpoint,
    /// iroh's relay map, shared with the endpoint. Its URLs never change; `set_auth_token` is
    /// its only write.
    map: RelayMap,
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
        // Direct addresses are the bound interfaces' only: with every relay's QUIC address
        // discovery off (`relay_config`), no port mapping either.
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Custom(relays.clone()))
            .portmapper_config(PortmapperConfig::Disabled);
        if relay_only {
            builder = builder.clear_ip_transports();
        }
        match builder.bind().await {
            Ok(endpoint) => Outcome::Handle(handle(wi_endpoint {
                endpoint,
                map: relays,
                alpn,
                close: RunOnce::new(),
                connections: Default::default(),
            })),
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
    let map = this.map.clone();
    let relay = relay_url(unsafe { text(relay_url_text) });
    let auth_token = unsafe { text(auth_token) };
    spawn(callback, context, async move {
        let relay = match relay {
            Ok(relay) => relay,
            Err(e) => return Outcome::Error(e),
        };
        if endpoint.is_closed() {
            return Outcome::Closed("endpoint closed".into());
        }
        if !map.contains(&relay) {
            return Outcome::Error(format!("relay URL {relay} is not in the endpoint's map"));
        }
        // The relay's connection actor reads the map at every dial, and a check restarts a dial
        // that presents a token the map no longer holds; a report would only cost time.
        map.insert(relay.clone(), relay_config(relay, auth_token));
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

/// How many addresses one `wi_endpoint_connect` may name: iroh keeps them, and sends to them,
/// while that dial is in flight and then for the connection it made.
const MAX_DIAL_ADDRESSES: usize = 16;

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
        let relay = match relay {
            Some(Ok(relay)) => Some(relay),
            Some(Err(e)) => return Outcome::Error(e),
            None => None,
        };
        if addresses.len() > MAX_DIAL_ADDRESSES {
            return Outcome::Error(format!(
                "{} addresses to dial, at most {MAX_DIAL_ADDRESSES}",
                addresses.len()
            ));
        }
        for text in addresses {
            match text.parse::<SocketAddr>() {
                Ok(ip) => address = address.with_ip_addr(ip),
                Err(e) => return Outcome::Error(format!("address {text}: {e}")),
            }
        }
        if let Some(relay) = &relay {
            address = address.with_relay_url(relay.clone());
        }
        if address.is_empty() {
            return Outcome::Error("neither a relay URL nor an address to dial".into());
        }
        if let Some(relay) = &relay {
            // A relay whose last connection failed has its connection actor waiting out a
            // redial backoff (up to 16 s): a retry ends it, so the dial's packets go out over a
            // fresh connection now. Only that relay's actor is touched.
            let failed = endpoint
                .relay_upgrade_failures()
                .get()
                .iter()
                .any(|status| status.url() == relay);
            if failed {
                endpoint.retry_relay(relay).await;
            }
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
    after_suspension: bool,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let endpoint = unsafe { &*endpoint }.endpoint.clone();
    spawn(callback, context, async move {
        if after_suspension {
            endpoint.network_change_after_suspension().await;
        } else {
            endpoint.network_change().await;
        }
        Outcome::Ok
    })
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, dead_code)]
pub enum wi_relay_kind {
    WI_RELAY_HOME_CONNECTED = 0,
    WI_RELAY_HOME_CONNECTING = 1,
    WI_RELAY_HOME_DISCONNECTED = 2,
    WI_RELAY_REACHABLE = 3,
    WI_RELAY_UNREACHABLE = 4,
    WI_RELAY_UNPROBED = 5,
    WI_RELAY_FAILED = 6,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_relay_state {
    url: *const c_char,
    kind: wi_relay_kind,
    last_error: *const c_char,
    latency_micros: u64,
}

struct RelayState {
    url: CString,
    kind: wi_relay_kind,
    last_error: Option<CString>,
    latency_micros: u64,
}

/// The endpoint's relays as one read saw them; its strings live as long as it does.
#[allow(non_camel_case_types)]
pub struct wi_relays(Vec<RelayState>);

fn c_string(text: &str) -> CString {
    CString::new(text.replace('\0', " ")).expect("no NUL")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_endpoint_relays(endpoint: *const wi_endpoint) -> *mut wi_relays {
    let this = unsafe { &*endpoint };
    guard(ptr::null_mut(), || {
        let home = this.endpoint.home_relay_status().get().into_iter().next();
        let report = this.endpoint.net_report().get();
        // Relays whose latest connection failed before it was established: iroh passes them
        // over as home while a report reached another relay.
        let failures = this.endpoint.relay_upgrade_failures().get();
        let mut urls: Vec<RelayUrl> = this.map.urls();
        urls.sort();
        let states = urls
            .iter()
            .map(|url| {
                let failure = failures.iter().find(|status| status.url() == url);
                let mut last_error = None;
                let mut latency_micros = 0;
                let kind = match (&home, &report) {
                    (Some(home), _) if home.url() == url => {
                        if home.is_connected() {
                            wi_relay_kind::WI_RELAY_HOME_CONNECTED
                        } else if let Some(error) = home.last_error() {
                            last_error = Some(format!("{error:#}"));
                            wi_relay_kind::WI_RELAY_HOME_DISCONNECTED
                        } else {
                            // iroh drops the home's error once a redial starts; the record
                            // keeps it until a connection is established.
                            last_error = failure
                                .and_then(|failure| failure.last_error())
                                .map(|error| format!("{error:#}"));
                            wi_relay_kind::WI_RELAY_HOME_CONNECTING
                        }
                    }
                    (_, _) if failure.is_some() => {
                        last_error = Some(
                            failure
                                .and_then(|failure| failure.last_error())
                                .map_or_else(
                                    || "connection failed before it was established".into(),
                                    |error| format!("{error:#}"),
                                ),
                        );
                        wi_relay_kind::WI_RELAY_FAILED
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
                            latency_micros = (latency.as_micros() as u64).max(1);
                            wi_relay_kind::WI_RELAY_REACHABLE
                        }
                        None => wi_relay_kind::WI_RELAY_UNREACHABLE,
                    },
                };
                RelayState {
                    url: c_string(url.as_str()),
                    kind,
                    last_error: last_error.as_deref().map(c_string),
                    latency_micros,
                }
            })
            .collect();
        handle(wi_relays(states)) as *mut wi_relays
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relays_count(relays: *const wi_relays) -> usize {
    let relays = unsafe { &*relays };
    guard(0, || relays.0.len())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relays_get(relays: *const wi_relays, index: usize) -> wi_relay_state {
    let relays = unsafe { &*relays };
    let missing = wi_relay_state {
        url: ptr::null(),
        kind: wi_relay_kind::WI_RELAY_UNPROBED,
        last_error: ptr::null(),
        latency_micros: 0,
    };
    guard(missing, || match relays.0.get(index) {
        Some(state) => wi_relay_state {
            url: state.url.as_ptr(),
            kind: state.kind,
            last_error: state
                .last_error
                .as_ref()
                .map_or(ptr::null(), |e| e.as_ptr()),
            latency_micros: state.latency_micros,
        },
        None => wi_relay_state {
            url: ptr::null(),
            kind: wi_relay_kind::WI_RELAY_UNPROBED,
            last_error: ptr::null(),
            latency_micros: 0,
        },
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relays_free(relays: *mut wi_relays) {
    guard((), || drop(unsafe { Box::from_raw(relays) }))
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
            endpoint
                .relay_upgrade_failures()
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
    remote: *mut c_char,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_connection_path(
    connection: *const wi_connection,
    out: *mut wi_path,
) -> bool {
    let connection = unsafe { &*connection };
    guard(false, || {
        let paths = connection.0.connection.paths();
        let Some(path) = paths
            .iter()
            .find(|p| p.is_selected())
            .or_else(|| paths.iter().next())
        else {
            return false;
        };
        let remote = match path.remote_addr() {
            iroh::TransportAddr::Relay(url) => url.to_string(),
            iroh::TransportAddr::Ip(address) => address.to_string(),
            other => format!("{other:?}"),
        };
        let value = wi_path {
            relay: path.is_relay(),
            rtt_micros: path.rtt().as_micros() as u64,
            remote: c_string(&remote).into_raw(),
        };
        unsafe { out.write(value) };
        true
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_string_free(text: *mut c_char) {
    if text.is_null() {
        return;
    }
    guard((), || drop(unsafe { CString::from_raw(text) }))
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

#[cfg(feature = "test-hooks")]
pub unsafe fn net_reports(endpoint: *const c_void) -> u64 {
    let this = unsafe { &*(endpoint as *const wi_endpoint) };
    this.endpoint.metrics().net_report.reports.get()
}

#[cfg(feature = "test-hooks")]
/// Runs full net reports and returns once one that started after the call was published, to
/// the endpoint's selection, with a probe of `relay`. Panics after 20 s without one.
pub unsafe fn run_net_report(endpoint: *const c_void, relay: &str) {
    let endpoint = unsafe { &*(endpoint as *const wi_endpoint) }
        .endpoint
        .clone();
    let relay: RelayUrl = relay.parse().expect("a relay URL");
    let runtime = runtime().expect("a runtime");
    runtime.block_on(async move {
        // Removing a relay the map doesn't hold changes no entry and no token, and asks for a
        // full report as every map change does.
        let absent: RelayUrl = "http://wuhu-iroh-report.invalid".parse().expect("a URL");
        let full = || endpoint.metrics().net_report.reports_full.get();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        let before = full();
        endpoint.remove_relay(&absent).await;
        // Once that full report started, a report running at the call has published or
        // stopped: what this watcher sees next comes from a full report started after the call.
        while full() < before + 1 {
            assert!(tokio::time::Instant::now() < deadline, "no full net report");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let mut published = endpoint.net_report();
        // That report may have published already: another full one follows it.
        endpoint.remove_relay(&absent).await;
        loop {
            let report = tokio::time::timeout_at(deadline, published.updated())
                .await
                .unwrap_or_else(|_| panic!("no full net report with a probe of {relay} published"))
                .expect("the endpoint is open");
            if report
                .is_some_and(|report| report.relay_latency.iter().any(|(_, url, _)| *url == relay))
            {
                return;
            }
        }
    });
}
