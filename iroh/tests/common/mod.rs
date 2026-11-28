//! Shared by the ABI test binaries.
#![allow(dead_code)]

use std::{
    ffi::{CStr, CString, c_char, c_void},
    net::{Shutdown, TcpListener, TcpStream},
    ptr,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

use wuhu_iroh as _;

#[repr(C)]
pub struct WiResult {
    pub status: i32,
    pub code: u64,
    pub handles: [*mut c_void; 2],
    pub bytes: *const u8,
    pub len: usize,
    pub message: *const c_char,
}

pub type Callback = unsafe extern "C" fn(*mut c_void, *const WiResult);

#[repr(C)]
pub struct Access {
    pub context: *mut c_void,
    pub on_connect:
        Option<unsafe extern "C" fn(*mut c_void, *const u8, u64, *const c_char) -> bool>,
    pub on_disconnect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64)>,
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct RelayEntry {
    pub url: *const c_char,
    pub auth_token: *const c_char,
}

pub const HOME_CONNECTED: u32 = 0;
pub const HOME_CONNECTING: u32 = 1;
pub const HOME_DISCONNECTED: u32 = 2;
pub const REACHABLE: u32 = 3;
pub const UNREACHABLE: u32 = 4;
pub const UNPROBED: u32 = 5;

pub fn is_home(kind: u32) -> bool {
    kind <= HOME_DISCONNECTED
}

#[repr(C)]
pub struct RelayState {
    pub url: [c_char; 256],
    pub kind: u32,
    pub last_error: [c_char; 256],
    pub latency_micros: u64,
}

impl RelayState {
    pub fn url(&self) -> String {
        unsafe { CStr::from_ptr(self.url.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    pub fn last_error(&self) -> String {
        unsafe { CStr::from_ptr(self.last_error.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }
}

unsafe extern "C" {
    pub fn wi_endpoint_set_auth_token(
        endpoint: *const c_void,
        relay_url: *const c_char,
        auth_token: *const c_char,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_endpoint_relays(
        endpoint: *const c_void,
        out: *mut RelayState,
        capacity: usize,
    ) -> usize;
    pub fn wi_endpoint_direct_addresses(
        endpoint: *const c_void,
        out: *mut c_char,
        capacity: usize,
    ) -> usize;
    pub fn wi_relay_spawn(
        address: *const c_char,
        cert: *const c_char,
        key: *const c_char,
        access: Access,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_relay_address(relay: *const c_void, out: *mut c_char, capacity: usize) -> usize;
    pub fn wi_relay_disconnect(relay: *const c_void, key: *const u8) -> bool;
    pub fn wi_relay_free(relay: *mut c_void);
    pub fn wi_endpoint_bind(
        secret: *const u8,
        relays: *const RelayEntry,
        relay_count: usize,
        relay_only: bool,
        alpn: *const u8,
        alpn_len: usize,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_endpoint_key(endpoint: *const c_void, out: *mut u8);
    pub fn wi_endpoint_connect(
        endpoint: *const c_void,
        key: *const u8,
        relay_url: *const c_char,
        addresses: *const *const c_char,
        address_count: usize,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_endpoint_watch(endpoint: *const c_void) -> *mut c_void;
    pub fn wi_watch_next(watch: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    pub fn wi_watch_free(watch: *mut c_void);
    pub fn wi_send_stopped(send: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    pub fn wi_recv_stop(recv: *const c_void, code: u64);
    pub fn wi_endpoint_accept(
        endpoint: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_endpoint_free(endpoint: *mut c_void);
    pub fn wi_connection_open(
        connection: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_connection_accept(
        connection: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_connection_closed(
        connection: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_connection_close(connection: *const c_void, code: u64);
    pub fn wi_connection_free(connection: *mut c_void);
    pub fn wi_send_write(
        send: *const c_void,
        bytes: *const u8,
        len: usize,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_send_finish(send: *const c_void) -> i32;
    pub fn wi_send_reset(send: *const c_void, code: u64);
    pub fn wi_send_free(send: *mut c_void);
    pub fn wi_recv_read(
        recv: *const c_void,
        max: usize,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_recv_free(recv: *mut c_void);
    pub fn wi_endpoint_close(
        endpoint: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_relay_shutdown(relay: *const c_void, callback: Callback, context: *mut c_void)
    -> u64;
    pub fn wi_cancel(operation: u64);
}

#[derive(Debug)]
pub struct Done {
    pub status: i32,
    pub code: u64,
    pub handles: [usize; 2],
    pub bytes: Vec<u8>,
    pub message: String,
}

pub unsafe extern "C" fn reply(context: *mut c_void, result: *const WiResult) {
    let sender = unsafe { Box::from_raw(context as *mut mpsc::Sender<Done>) };
    let result = unsafe { &*result };
    let bytes = if result.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(result.bytes, result.len) }.to_vec()
    };
    let message = if result.message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(result.message) }
            .to_string_lossy()
            .into_owned()
    };
    let _ = sender.send(Done {
        status: result.status,
        code: result.code,
        handles: [result.handles[0] as usize, result.handles[1] as usize],
        bytes,
        message,
    });
}

pub fn call(start: impl FnOnce(Callback, *mut c_void) -> u64) -> mpsc::Receiver<Done> {
    let (sender, receiver) = mpsc::channel();
    start(reply, Box::into_raw(Box::new(sender)) as *mut c_void);
    receiver
}

pub fn wait(receiver: mpsc::Receiver<Done>) -> Done {
    receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("callback within 10 s")
}

pub fn ok(receiver: mpsc::Receiver<Done>) -> Done {
    let done = wait(receiver);
    assert_eq!(done.status, 0, "{done:?}");
    done
}

pub const DENIED: [u8; 32] = [9; 32];

pub unsafe extern "C" fn admit(_: *mut c_void, _key: *const u8, _: u64, _: *const c_char) -> bool {
    true
}

/// An open relay on localhost and its URL.
pub fn spawn_relay() -> (*mut c_void, CString) {
    let access = Access {
        context: ptr::null_mut(),
        on_connect: Some(admit),
        on_disconnect: None,
        release: None,
    };
    spawn_relay_access(access)
}

pub fn spawn_relay_with(
    on_connect: unsafe extern "C" fn(*mut c_void, *const u8, u64, *const c_char) -> bool,
    on_disconnect: unsafe extern "C" fn(*mut c_void, *const u8, u64),
) -> (*mut c_void, CString) {
    spawn_relay_access(Access {
        context: ptr::null_mut(),
        on_connect: Some(on_connect),
        on_disconnect: Some(on_disconnect),
        release: None,
    })
}

pub fn spawn_relay_access(access: Access) -> (*mut c_void, CString) {
    let http = CString::new("127.0.0.1:0").unwrap();
    let relay = ok(call(|cb, cx| unsafe {
        wi_relay_spawn(http.as_ptr(), ptr::null(), ptr::null(), access, cb, cx)
    }))
    .handles[0] as *mut c_void;
    let mut address = [0 as c_char; 64];
    let len = unsafe { wi_relay_address(relay, address.as_mut_ptr(), 64) };
    assert!(len > 0);
    let url = format!(
        "http://{}",
        unsafe { CStr::from_ptr(address.as_ptr()) }
            .to_str()
            .unwrap()
    );
    (relay, CString::new(url).unwrap())
}

pub fn bind(seed: u8, url: &CString) -> *mut c_void {
    bind_to(seed, &[(url, None)])
}

/// A relay-only endpoint over `relays`, each with its token or none.
pub fn bind_to(seed: u8, relays: &[(&CString, Option<&CString>)]) -> *mut c_void {
    let secret = [seed; 32];
    let alpn = b"wuhu/test/0";
    let entries: Vec<RelayEntry> = relays
        .iter()
        .map(|(url, token)| RelayEntry {
            url: url.as_ptr(),
            auth_token: token.map_or(ptr::null(), |token| token.as_ptr()),
        })
        .collect();
    ok(call(|cb, cx| unsafe {
        wi_endpoint_bind(
            secret.as_ptr(),
            entries.as_ptr(),
            entries.len(),
            true,
            alpn.as_ptr(),
            alpn.len(),
            cb,
            cx,
        )
    }))
    .handles[0] as *mut c_void
}

/// Dials `key` through `url`.
pub fn dial(endpoint: *mut c_void, key: &[u8; 32], url: &CString) -> mpsc::Receiver<Done> {
    call(|cb, cx| unsafe {
        wi_endpoint_connect(endpoint, key.as_ptr(), url.as_ptr(), ptr::null(), 0, cb, cx)
    })
}

/// The endpoint's relay states, in URL order.
pub fn relays(endpoint: *mut c_void) -> Vec<RelayState> {
    let count = unsafe { wi_endpoint_relays(endpoint, ptr::null_mut(), 0) };
    let mut states: Vec<RelayState> = (0..count)
        .map(|_| RelayState {
            url: [0; 256],
            kind: 99,
            last_error: [0; 256],
            latency_micros: 0,
        })
        .collect();
    let filled = unsafe { wi_endpoint_relays(endpoint, states.as_mut_ptr(), states.len()) };
    assert_eq!(filled, count);
    states
}

/// The URL of the endpoint's home relay once it is connected there.
pub fn connected_home(endpoint: *mut c_void) -> Option<String> {
    relays(endpoint)
        .into_iter()
        .find(|state| state.kind == HOME_CONNECTED)
        .map(|state| state.url())
}

pub static SHUT_OUT: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
pub static GONE: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

pub unsafe extern "C" fn admit_unless_shut_out(
    _: *mut c_void,
    key: *const u8,
    _: u64,
    _: *const c_char,
) -> bool {
    let key = unsafe { *(key as *const [u8; 32]) };
    !SHUT_OUT.lock().unwrap().contains(&key)
}

pub unsafe extern "C" fn record_gone(_: *mut c_void, key: *const u8, _: u64) {
    GONE.lock()
        .unwrap()
        .push(unsafe { *(key as *const [u8; 32]) });
}

/// Polls every 10 ms, for at most `limit`.
pub fn eventually(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

fn connect([server, client]: [*mut c_void; 2], url: &CString) -> [*mut c_void; 2] {
    let mut server_key = [0u8; 32];
    unsafe { wi_endpoint_key(server, server_key.as_mut_ptr()) };
    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing = ok(dial(client, &server_key, url)).handles[0] as *mut c_void;
    [outgoing, ok(accepted).handles[0] as *mut c_void]
}

/// Two endpoints on one open relay, the client's connection to the server and the server's side.
pub struct Link {
    pub relay: *mut c_void,
    pub url: CString,
    pub endpoints: [*mut c_void; 2],
    pub outgoing: *mut c_void,
    pub incoming: *mut c_void,
}

impl Link {
    pub fn new(seeds: [u8; 2]) -> Self {
        let (relay, url) = spawn_relay();
        let server = bind(seeds[0], &url);
        let client = bind(seeds[1], &url);
        let [outgoing, incoming] = connect([server, client], &url);
        Link {
            relay,
            url,
            endpoints: [server, client],
            outgoing,
            incoming,
        }
    }

    /// Another connection from the client, and the server's side of it.
    pub fn connect(&self) -> [*mut c_void; 2] {
        connect(self.endpoints, &self.url)
    }

    /// A stream from the client, and the server's side of it once `first` reached it.
    pub fn stream(&self, first: &[u8]) -> ([*mut c_void; 2], [*mut c_void; 2]) {
        let opened = ok(call(|cb, cx| unsafe {
            wi_connection_open(self.outgoing, cb, cx)
        }));
        let ours = [
            opened.handles[0] as *mut c_void,
            opened.handles[1] as *mut c_void,
        ];
        ok(call(|cb, cx| unsafe {
            wi_send_write(ours[0], first.as_ptr(), first.len(), cb, cx)
        }));
        let accepted = ok(call(|cb, cx| unsafe {
            wi_connection_accept(self.incoming, cb, cx)
        }));
        (
            ours,
            [
                accepted.handles[0] as *mut c_void,
                accepted.handles[1] as *mut c_void,
            ],
        )
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        unsafe {
            wi_connection_free(self.outgoing);
            wi_connection_free(self.incoming);
            for endpoint in self.endpoints {
                ok(call(|cb, cx| wi_endpoint_close(endpoint, cb, cx)));
                wi_endpoint_free(endpoint);
            }
            wi_relay_free(self.relay);
        }
    }
}

pub fn read_to_end(recv: *mut c_void) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let read = wait(call(|cb, cx| unsafe {
            wi_recv_read(recv, 1 << 20, cb, cx)
        }));
        match read.status {
            0 => bytes.extend(read.bytes),
            1 => return bytes,
            _ => panic!("{read:?}"),
        }
    }
}

/// A plain TCP forwarder to `target` that holds each new connection 40 ms before forwarding it, so a
/// relay behind it probes slower than one reached directly.
pub fn slow_proxy(target: &CString) -> CString {
    let target = target
        .to_str()
        .unwrap()
        .trim_start_matches("http://")
        .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = CString::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let target = target.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(40));
                let Ok(server) = TcpStream::connect(&target) else {
                    return;
                };
                let (mut c, mut s) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c, &mut s);
                    let _ = s.shutdown(Shutdown::Write);
                });
                let (mut s, mut c) = (server, client);
                let _ = std::io::copy(&mut s, &mut c);
                let _ = c.shutdown(Shutdown::Write);
            });
        }
    });
    url
}
