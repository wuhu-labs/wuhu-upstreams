//! A connection's close reports the close that took effect: the one the peer saw.

mod common;

use std::{
    ffi::c_void,
    sync::{Arc, Barrier},
};

use common::*;

fn closed(connection: *mut c_void) -> Done {
    let closed = wait(call(|cb, cx| unsafe { wi_connection_closed(connection, cb, cx) }));
    assert_eq!(closed.status, 4, "{closed:?}");
    closed
}

#[test]
fn a_close_after_the_endpoint_closed_the_connection_keeps_its_cause() {
    let link = Link::new([31, 32]);
    ok(call(|cb, cx| unsafe { wi_endpoint_close(link.endpoints[1], cb, cx) }));
    assert_eq!(closed(link.outgoing).code, 0);
    unsafe { wi_connection_close(link.outgoing, 7) };
    assert_eq!(closed(link.outgoing).code, 0, "the endpoint's close took effect, not ours");
    assert_eq!(closed(link.incoming).code, 0, "the peer saw the endpoint's close");
}

#[test]
fn concurrent_closes_report_the_code_the_peer_saw() {
    let link = Link::new([33, 34]);
    for _ in 0..400 {
        let [outgoing, incoming] = link.connect();
        let barrier = Arc::new(Barrier::new(2));
        let closers = [5u64, 6].map(|code| {
            let (barrier, outgoing) = (barrier.clone(), outgoing as usize);
            std::thread::spawn(move || {
                barrier.wait();
                unsafe { wi_connection_close(outgoing as *const c_void, code) };
            })
        });
        for closer in closers {
            closer.join().unwrap();
        }
        let (ours, theirs) = (closed(outgoing).code, closed(incoming).code);
        assert!(ours == 5 || ours == 6, "{ours}");
        assert_eq!(ours, theirs, "ours reports {ours}, the peer saw {theirs}");
        unsafe {
            wi_connection_free(outgoing);
            wi_connection_free(incoming);
        }
    }
}
