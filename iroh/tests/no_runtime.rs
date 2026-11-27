//! An entry point called when the host cannot give the runtime its threads replies ERROR instead
//! of aborting the process. Its own test binary: the runtime must not have started before.

#![cfg(target_os = "linux")]

use std::{
    ffi::{c_char, c_void},
    sync::Mutex,
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

unsafe extern "C" {
    fn wi_endpoint_bind(
        secret: *const u8,
        relay: *const c_char,
        relay_only: bool,
        alpn: *const u8,
        alpn_len: usize,
        callback: unsafe extern "C" fn(*mut c_void, *const WiResult),
        context: *mut c_void,
    ) -> u64;
}

static SEEN: Mutex<Vec<i32>> = Mutex::new(Vec::new());

unsafe extern "C" fn record(_: *mut c_void, result: *const WiResult) {
    SEEN.lock().unwrap().push(unsafe { (*result).status });
}

#[test]
fn without_threads_an_operation_ends_in_error_on_the_calling_thread() {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limit) }, 0);
    limit.rlim_cur = 1;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) }, 0);
    let secret = [1u8; 32];
    let relay = c"http://127.0.0.1:1";
    let alpn = b"wuhu/test/0";
    unsafe {
        wi_endpoint_bind(
            secret.as_ptr(),
            relay.as_ptr(),
            true,
            alpn.as_ptr(),
            alpn.len(),
            record,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(*SEEN.lock().unwrap(), vec![6]);
}
