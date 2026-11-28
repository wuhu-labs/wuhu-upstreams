//! The send half against our own reset and finish, on one long-lived connection.

mod common;

use std::{
    ffi::c_void,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use common::*;

fn soon(receiver: std::sync::mpsc::Receiver<Done>) -> Done {
    receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("callback within 2 s")
}

/// The peer's reading until the stream ends, by its reset or its finish.
fn read_to_reset(recv: *mut c_void) -> Done {
    loop {
        let read = wait(call(|cb, cx| unsafe {
            wi_recv_read(recv, 1 << 20, cb, cx)
        }));
        if read.status != 0 {
            return read;
        }
    }
}

#[test]
fn a_local_reset_ends_stopped_at_once_with_its_code_again_and_again() {
    let link = Link::new([21, 22]);
    for _ in 0..20 {
        let ([send, recv], [peer_send, peer_recv]) = link.stream(b"x");
        let pending = call(|cb, cx| unsafe { wi_send_stopped(send, cb, cx) });
        unsafe { wi_send_reset(send, 5) };
        let pending = soon(pending);
        assert_eq!(
            (pending.status, pending.code),
            (2, 5),
            "pending: {pending:?}"
        );
        let read = read_to_reset(peer_recv);
        assert_eq!((read.status, read.code), (2, 5), "the peer reads the reset");
        let later = soon(call(|cb, cx| unsafe { wi_send_stopped(send, cb, cx) }));
        assert_eq!((later.status, later.code), (2, 5), "later: {later:?}");
        unsafe {
            wi_send_free(send);
            wi_recv_free(recv);
            wi_send_free(peer_send);
            wi_recv_free(peer_recv);
        }
    }
}

#[test]
fn a_local_reset_ends_a_write_blocked_on_flow_control() {
    let link = Link::new([23, 24]);
    let ([send, recv], [peer_send, peer_recv]) = link.stream(b"x");
    let body = vec![7u8; 16 << 20];
    let write = call(|cb, cx| unsafe { wi_send_write(send, body.as_ptr(), body.len(), cb, cx) });
    unsafe { wi_send_reset(send, 4) };
    let write = soon(write);
    assert_eq!((write.status, write.code), (2, 4), "{write:?}");
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
}

#[test]
fn a_finish_while_a_write_copies_its_bytes_finishes_nothing() {
    let link = Link::new([25, 26]);
    let ([send, recv], [peer_send, peer_recv]) = link.stream(b"x");
    let body = vec![7u8; 128 << 20];
    let calling = Arc::new(AtomicBool::new(false));
    let returned = Arc::new(AtomicBool::new(false));
    let finisher = {
        let (calling, returned, send) = (calling.clone(), returned.clone(), send as usize);
        std::thread::spawn(move || {
            while !calling.load(Ordering::SeqCst) {}
            // Into the copy of the bytes, which takes tens of milliseconds.
            std::thread::sleep(Duration::from_millis(5));
            let mut finishes = Vec::new();
            while !returned.load(Ordering::SeqCst) {
                finishes.push(unsafe { wi_send_finish(send as *const c_void) });
            }
            finishes
        })
    };
    calling.store(true, Ordering::SeqCst);
    let write = call(|cb, cx| unsafe { wi_send_write(send, body.as_ptr(), body.len(), cb, cx) });
    returned.store(true, Ordering::SeqCst);
    let finishes = finisher.join().unwrap();
    assert!(!finishes.is_empty(), "the finisher ran during the call");
    let finished = finishes.iter().filter(|&&f| f != 6).count();
    assert_eq!(
        finished,
        0,
        "of {} finishes during the call, {finished} were not ERROR",
        finishes.len()
    );
    unsafe { wi_send_reset(send, 0) };
    assert_eq!(wait(write).status, 2);
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
}
