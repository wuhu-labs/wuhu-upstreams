//! The C ABI end to end on localhost: a relay, two relay-only endpoints, one echoed stream.

use std::{
    ffi::{CStr, CString, c_char, c_void},
    ptr,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

use wuhu_iroh as _;

#[repr(C)]
struct WiResult {
    status: i32,
    code: u64,
    handles: [*mut c_void; 2],
    bytes: *const u8,
    len: usize,
    message: *const c_char,
}

type Callback = unsafe extern "C" fn(*mut c_void, *const WiResult);

#[repr(C)]
struct Access {
    context: *mut c_void,
    on_connect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64) -> bool>,
    on_disconnect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64)>,
    release: Option<unsafe extern "C" fn(*mut c_void)>,
}

unsafe extern "C" {
    fn wi_relay_spawn(
        http: *const c_char,
        tls: *const c_char,
        cert: *const c_char,
        key: *const c_char,
        access: Access,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    fn wi_relay_address(relay: *const c_void, tls: bool, out: *mut c_char, capacity: usize)
    -> usize;
    fn wi_relay_disconnect(relay: *const c_void, key: *const u8) -> bool;
    fn wi_relay_free(relay: *mut c_void);
    fn wi_endpoint_bind(
        secret: *const u8,
        relay: *const c_char,
        relay_only: bool,
        alpn: *const u8,
        alpn_len: usize,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    fn wi_endpoint_key(endpoint: *const c_void, out: *mut u8);
    fn wi_endpoint_connect(
        endpoint: *const c_void,
        key: *const u8,
        relay: *const c_char,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    fn wi_endpoint_accept(endpoint: *const c_void, callback: Callback, context: *mut c_void)
    -> u64;
    fn wi_endpoint_free(endpoint: *mut c_void);
    fn wi_connection_open(connection: *const c_void, callback: Callback, context: *mut c_void)
    -> u64;
    fn wi_connection_accept(
        connection: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    fn wi_connection_closed(
        connection: *const c_void,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    fn wi_connection_close(connection: *const c_void, code: u64);
    fn wi_connection_free(connection: *mut c_void);
    fn wi_send_write(
        send: *const c_void,
        bytes: *const u8,
        len: usize,
        callback: Callback,
        context: *mut c_void,
    ) -> u64;
    fn wi_send_finish(send: *const c_void) -> bool;
    fn wi_send_free(send: *mut c_void);
    fn wi_recv_read(recv: *const c_void, max: usize, callback: Callback, context: *mut c_void)
    -> u64;
    fn wi_recv_free(recv: *mut c_void);
    fn wi_endpoint_close(endpoint: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    fn wi_relay_shutdown(relay: *const c_void, callback: Callback, context: *mut c_void) -> u64;
    fn wi_cancel(operation: u64);
}

#[derive(Debug)]
struct Done {
    status: i32,
    code: u64,
    handles: [usize; 2],
    bytes: Vec<u8>,
    message: String,
}

unsafe extern "C" fn reply(context: *mut c_void, result: *const WiResult) {
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

fn call(start: impl FnOnce(Callback, *mut c_void) -> u64) -> mpsc::Receiver<Done> {
    let (sender, receiver) = mpsc::channel();
    start(reply, Box::into_raw(Box::new(sender)) as *mut c_void);
    receiver
}

fn wait(receiver: mpsc::Receiver<Done>) -> Done {
    receiver.recv_timeout(Duration::from_secs(10)).expect("callback within 10 s")
}

fn ok(receiver: mpsc::Receiver<Done>) -> Done {
    let done = wait(receiver);
    assert_eq!(done.status, 0, "{done:?}");
    done
}

const DENIED: [u8; 32] = [9; 32];

unsafe extern "C" fn admit(_: *mut c_void, _key: *const u8, _: u64) -> bool {
    true
}

/// An open relay on localhost and its URL.
fn spawn_relay() -> (*mut c_void, CString) {
    let access = Access {
        context: ptr::null_mut(),
        on_connect: Some(admit),
        on_disconnect: None,
        release: None,
    };
    spawn_relay_access(access)
}

fn spawn_relay_with(
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

fn spawn_relay_access(access: Access) -> (*mut c_void, CString) {
    let http = CString::new("127.0.0.1:0").unwrap();
    let relay = ok(call(|cb, cx| unsafe {
        wi_relay_spawn(http.as_ptr(), ptr::null(), ptr::null(), ptr::null(), access, cb, cx)
    }))
    .handles[0] as *mut c_void;
    let mut address = [0 as c_char; 64];
    let len = unsafe { wi_relay_address(relay, false, address.as_mut_ptr(), 64) };
    assert!(len > 0);
    let url = format!(
        "http://{}",
        unsafe { CStr::from_ptr(address.as_ptr()) }.to_str().unwrap()
    );
    (relay, CString::new(url).unwrap())
}

fn bind(seed: u8, url: &CString) -> *mut c_void {
    let secret = [seed; 32];
    let alpn = b"wuhu/test/0";
    ok(call(|cb, cx| unsafe {
        wi_endpoint_bind(secret.as_ptr(), url.as_ptr(), true, alpn.as_ptr(), alpn.len(), cb, cx)
    }))
    .handles[0] as *mut c_void
}

static SHUT_OUT: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
static GONE: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

unsafe extern "C" fn admit_unless_shut_out(_: *mut c_void, key: *const u8, _: u64) -> bool {
    let key = unsafe { *(key as *const [u8; 32]) };
    !SHUT_OUT.lock().unwrap().contains(&key)
}

unsafe extern "C" fn record_gone(_: *mut c_void, key: *const u8, _: u64) {
    GONE.lock().unwrap().push(unsafe { *(key as *const [u8; 32]) });
}

/// Polls every 10 ms, for at most `limit`.
fn eventually(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

/// The server drops off the relay for good, so the client's close drains for a while: the
/// cancel lands mid-close, after iroh marked the endpoint closing and before it stopped.
#[test]
fn a_close_cancelled_midway_still_runs_to_its_end() {
    let (relay, url) = spawn_relay_with(admit_unless_shut_out, record_gone);
    let server = bind(3, &url);
    let client = bind(4, &url);
    let (mut server_key, mut client_key) = ([0u8; 32], [0u8; 32]);
    unsafe {
        wi_endpoint_key(server, server_key.as_mut_ptr());
        wi_endpoint_key(client, client_key.as_mut_ptr());
    }
    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing = ok(call(|cb, cx| unsafe {
        wi_endpoint_connect(client, server_key.as_ptr(), url.as_ptr(), cb, cx)
    }))
    .handles[0] as *mut c_void;
    let incoming = ok(accepted).handles[0] as *mut c_void;
    let opened = ok(call(|cb, cx| unsafe { wi_connection_open(outgoing, cb, cx) }));
    let (send, recv) = (opened.handles[0] as *mut c_void, opened.handles[1] as *mut c_void);
    ok(call(|cb, cx| unsafe { wi_send_write(send, b"hi".as_ptr(), 2, cb, cx) }));
    let pending = call(|cb, cx| unsafe { wi_recv_read(recv, 65536, cb, cx) });

    SHUT_OUT.lock().unwrap().push(server_key);
    assert!(unsafe { wi_relay_disconnect(relay, server_key.as_ptr()) });
    let first = call(|cb, cx| unsafe {
        let id = wi_endpoint_close(client, cb, cx);
        std::thread::sleep(Duration::from_millis(20));
        wi_cancel(id);
        id
    });
    let first = wait(first);
    assert!(first.status == 5 || first.status == 0, "{first:?}");
    ok(call(|cb, cx| unsafe { wi_endpoint_close(client, cb, cx) }));
    assert_eq!(wait(pending).status, 4, "the in-flight read ends with the close");
    assert!(
        eventually(Duration::from_secs(2), || GONE.lock().unwrap().contains(&client_key)),
        "the client's relay connection ended with its close",
    );

    let first = wait(call(|cb, cx| unsafe {
        let id = wi_relay_shutdown(relay, cb, cx);
        wi_cancel(id);
        id
    }));
    assert!(first.status == 5 || first.status == 0, "{first:?}");
    ok(call(|cb, cx| unsafe { wi_relay_shutdown(relay, cb, cx) }));
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
        wi_endpoint_free(client);
        wi_endpoint_free(server);
        wi_relay_free(relay);
    }
}

#[test]
fn echo_through_relay_and_kick() {
    let (relay, url) = spawn_relay();
    let bind = |seed: u8| bind(seed, &url);
    let server = bind(1);
    let client = bind(2);
    let mut server_key = [0u8; 32];
    let mut client_key = [0u8; 32];
    unsafe {
        wi_endpoint_key(server, server_key.as_mut_ptr());
        wi_endpoint_key(client, client_key.as_mut_ptr());
    }

    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let dialled = ok(call(|cb, cx| unsafe {
        wi_endpoint_connect(client, server_key.as_ptr(), url.as_ptr(), cb, cx)
    }));
    assert_eq!(dialled.bytes, server_key);
    let outgoing = dialled.handles[0] as *mut c_void;

    let (send, recv) = {
        let opened = ok(call(|cb, cx| unsafe { wi_connection_open(outgoing, cb, cx) }));
        (opened.handles[0] as *mut c_void, opened.handles[1] as *mut c_void)
    };
    ok(call(|cb, cx| unsafe { wi_send_write(send, b"ping".as_ptr(), 4, cb, cx) }));
    assert!(unsafe { wi_send_finish(send) });

    let accepted = ok(accepted);
    assert_eq!(accepted.bytes, client_key, "accept carries the caller's key");
    let incoming = accepted.handles[0] as *mut c_void;
    let stream = ok(call(|cb, cx| unsafe { wi_connection_accept(incoming, cb, cx) }));
    let (peer_send, peer_recv) = (stream.handles[0] as *mut c_void, stream.handles[1] as *mut c_void);
    let mut request = Vec::new();
    loop {
        let read = wait(call(|cb, cx| unsafe { wi_recv_read(peer_recv, 65536, cb, cx) }));
        match read.status {
            0 => request.extend(read.bytes),
            1 => break,
            _ => panic!("{read:?}"),
        }
    }
    assert_eq!(request, b"ping");
    ok(call(|cb, cx| unsafe { wi_send_write(peer_send, request.as_ptr(), request.len(), cb, cx) }));
    assert!(unsafe { wi_send_finish(peer_send) });

    let read = ok(call(|cb, cx| unsafe { wi_recv_read(recv, 65536, cb, cx) }));
    assert_eq!(read.bytes, b"ping");
    assert_eq!(wait(call(|cb, cx| unsafe { wi_recv_read(recv, 65536, cb, cx) })).status, 1);

    let pending = call(|cb, cx| unsafe {
        let id = wi_recv_read(peer_recv, 1, cb, cx);
        wi_cancel(id);
        id
    });
    let cancelled = wait(pending);
    assert!(cancelled.status == 5 || cancelled.status == 1, "{cancelled:?}");

    assert!(unsafe { wi_relay_disconnect(relay, client_key.as_ptr()) });
    assert!(!unsafe { wi_relay_disconnect(relay, DENIED.as_ptr()) });

    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
    let closed = call(|cb, cx| unsafe { wi_connection_closed(incoming, cb, cx) });
    unsafe { wi_connection_close(outgoing, 7) };
    let closed = wait(closed);
    assert_eq!((closed.status, closed.code), (4, 7), "{}", closed.message);
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
        wi_endpoint_free(client);
        wi_endpoint_free(server);
        wi_relay_free(relay);
    }
}
