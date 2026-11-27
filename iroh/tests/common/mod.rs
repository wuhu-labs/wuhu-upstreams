//! Shared by the ABI test binaries.
#![allow(dead_code)]

use std::{
    ffi::{CStr, CString, c_char, c_void},
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
    pub on_connect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64) -> bool>,
    pub on_disconnect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64)>,
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
}

unsafe extern "C" {
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
        relay: *const c_char,
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
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    pub fn wi_endpoint_relay_watch(endpoint: *const c_void) -> *mut c_void;
    pub fn wi_watch_next(watch: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    pub fn wi_watch_free(watch: *mut c_void);
    pub fn wi_send_stopped(send: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    pub fn wi_recv_stop(recv: *const c_void, code: u64);
    pub fn wi_endpoint_accept(endpoint: *const c_void, callback: Callback, context: *mut c_void)
    -> u64;
    pub fn wi_endpoint_free(endpoint: *mut c_void);
    pub fn wi_connection_open(connection: *const c_void, callback: Callback, context: *mut c_void)
    -> u64;
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
    pub fn wi_recv_read(recv: *const c_void, max: usize, callback: Callback, context: *mut c_void)
    -> u64;
    pub fn wi_recv_free(recv: *mut c_void);
    pub fn wi_endpoint_close(endpoint: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    pub fn wi_relay_shutdown(relay: *const c_void, callback: Callback, context: *mut c_void) -> u64;
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
        unsafe { CStr::from_ptr(result.message) }.to_string_lossy().into_owned()
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
    receiver.recv_timeout(Duration::from_secs(10)).expect("callback within 10 s")
}

pub fn ok(receiver: mpsc::Receiver<Done>) -> Done {
    let done = wait(receiver);
    assert_eq!(done.status, 0, "{done:?}");
    done
}

pub const DENIED: [u8; 32] = [9; 32];

pub unsafe extern "C" fn admit(_: *mut c_void, _key: *const u8, _: u64) -> bool {
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
    on_connect: unsafe extern "C" fn(*mut c_void, *const u8, u64) -> bool,
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
        unsafe { CStr::from_ptr(address.as_ptr()) }.to_str().unwrap()
    );
    (relay, CString::new(url).unwrap())
}

pub fn bind(seed: u8, url: &CString) -> *mut c_void {
    let secret = [seed; 32];
    let alpn = b"wuhu/test/0";
    ok(call(|cb, cx| unsafe {
        wi_endpoint_bind(secret.as_ptr(), url.as_ptr(), true, alpn.as_ptr(), alpn.len(), cb, cx)
    }))
    .handles[0] as *mut c_void
}

pub static SHUT_OUT: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
pub static GONE: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

pub unsafe extern "C" fn admit_unless_shut_out(_: *mut c_void, key: *const u8, _: u64) -> bool {
    let key = unsafe { *(key as *const [u8; 32]) };
    !SHUT_OUT.lock().unwrap().contains(&key)
}

pub unsafe extern "C" fn record_gone(_: *mut c_void, key: *const u8, _: u64) {
    GONE.lock().unwrap().push(unsafe { *(key as *const [u8; 32]) });
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

fn connect([server, client]: [*mut c_void; 2]) -> [*mut c_void; 2] {
    let mut server_key = [0u8; 32];
    unsafe { wi_endpoint_key(server, server_key.as_mut_ptr()) };
    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing = ok(call(|cb, cx| unsafe {
        wi_endpoint_connect(client, server_key.as_ptr(), cb, cx)
    }))
    .handles[0] as *mut c_void;
    [outgoing, ok(accepted).handles[0] as *mut c_void]
}

/// Two endpoints on one open relay, the client's connection to the server and the server's side.
pub struct Link {
    pub relay: *mut c_void,
    pub endpoints: [*mut c_void; 2],
    pub outgoing: *mut c_void,
    pub incoming: *mut c_void,
}

impl Link {
    pub fn new(seeds: [u8; 2]) -> Self {
        let (relay, url) = spawn_relay();
        let server = bind(seeds[0], &url);
        let client = bind(seeds[1], &url);
        let [outgoing, incoming] = connect([server, client]);
        Link {
            relay,
            endpoints: [server, client],
            outgoing,
            incoming,
        }
    }

    /// Another connection from the client, and the server's side of it.
    pub fn connect(&self) -> [*mut c_void; 2] {
        connect(self.endpoints)
    }

    /// A stream from the client, and the server's side of it once `first` reached it.
    pub fn stream(&self, first: &[u8]) -> ([*mut c_void; 2], [*mut c_void; 2]) {
        let opened = ok(call(|cb, cx| unsafe { wi_connection_open(self.outgoing, cb, cx) }));
        let ours = [opened.handles[0] as *mut c_void, opened.handles[1] as *mut c_void];
        ok(call(|cb, cx| unsafe { wi_send_write(ours[0], first.as_ptr(), first.len(), cb, cx) }));
        let accepted = ok(call(|cb, cx| unsafe { wi_connection_accept(self.incoming, cb, cx) }));
        (ours, [accepted.handles[0] as *mut c_void, accepted.handles[1] as *mut c_void])
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
        let read = wait(call(|cb, cx| unsafe { wi_recv_read(recv, 1 << 20, cb, cx) }));
        match read.status {
            0 => bytes.extend(read.bytes),
            1 => return bytes,
            _ => panic!("{read:?}"),
        }
    }
}

