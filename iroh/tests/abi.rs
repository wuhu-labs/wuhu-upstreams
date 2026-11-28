//! The C ABI end to end on localhost: a relay, relay-only endpoints, streams between them.

mod common;

use std::{
    ffi::{CStr, CString, c_char, c_void},
    ptr,
    time::Duration,
};

use common::*;
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
    let outgoing = ok(dial(client, &server_key, &url)).handles[0] as *mut c_void;
    let incoming = ok(accepted).handles[0] as *mut c_void;
    let opened = ok(call(|cb, cx| unsafe {
        wi_connection_open(outgoing, cb, cx)
    }));
    let (send, recv) = (
        opened.handles[0] as *mut c_void,
        opened.handles[1] as *mut c_void,
    );
    ok(call(|cb, cx| unsafe {
        wi_send_write(send, b"hi".as_ptr(), 2, cb, cx)
    }));
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
    assert_eq!(
        wait(pending).status,
        4,
        "the in-flight read ends with the close"
    );
    assert!(
        eventually(Duration::from_secs(2), || GONE
            .lock()
            .unwrap()
            .contains(&client_key)),
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
    let dialled = ok(dial(client, &server_key, &url));
    assert_eq!(dialled.bytes, server_key);
    let outgoing = dialled.handles[0] as *mut c_void;

    let (send, recv) = {
        let opened = ok(call(|cb, cx| unsafe {
            wi_connection_open(outgoing, cb, cx)
        }));
        (
            opened.handles[0] as *mut c_void,
            opened.handles[1] as *mut c_void,
        )
    };
    ok(call(|cb, cx| unsafe {
        wi_send_write(send, b"ping".as_ptr(), 4, cb, cx)
    }));
    assert_eq!(unsafe { wi_send_finish(send) }, 0);

    let accepted = ok(accepted);
    assert_eq!(
        accepted.bytes, client_key,
        "accept carries the caller's key"
    );
    let incoming = accepted.handles[0] as *mut c_void;
    let stream = ok(call(|cb, cx| unsafe {
        wi_connection_accept(incoming, cb, cx)
    }));
    let (peer_send, peer_recv) = (
        stream.handles[0] as *mut c_void,
        stream.handles[1] as *mut c_void,
    );
    let mut request = Vec::new();
    loop {
        let read = wait(call(|cb, cx| unsafe {
            wi_recv_read(peer_recv, 65536, cb, cx)
        }));
        match read.status {
            0 => request.extend(read.bytes),
            1 => break,
            _ => panic!("{read:?}"),
        }
    }
    assert_eq!(request, b"ping");
    ok(call(|cb, cx| unsafe {
        wi_send_write(peer_send, request.as_ptr(), request.len(), cb, cx)
    }));
    assert_eq!(unsafe { wi_send_finish(peer_send) }, 0);

    let read = ok(call(|cb, cx| unsafe { wi_recv_read(recv, 65536, cb, cx) }));
    assert_eq!(read.bytes, b"ping");
    assert_eq!(
        wait(call(|cb, cx| unsafe { wi_recv_read(recv, 65536, cb, cx) })).status,
        1
    );

    let pending = call(|cb, cx| unsafe {
        let id = wi_recv_read(peer_recv, 1, cb, cx);
        wi_cancel(id);
        id
    });
    let cancelled = wait(pending);
    assert!(
        cancelled.status == 5 || cancelled.status == 1,
        "{cancelled:?}"
    );

    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
    let closed = call(|cb, cx| unsafe { wi_connection_closed(incoming, cb, cx) });
    let closed_here = call(|cb, cx| unsafe { wi_connection_closed(outgoing, cb, cx) });
    unsafe { wi_connection_close(outgoing, 7) };
    let closed = wait(closed);
    assert_eq!((closed.status, closed.code), (4, 7), "{}", closed.message);
    let closed_here = wait(closed_here);
    assert_eq!(
        (closed_here.status, closed_here.code),
        (4, 7),
        "our own close reports our code"
    );
    // The kick comes after the close: a close sent while the client is off the relay can be lost,
    // and the server's connection then ends later with code 0 (seen once in CI).
    assert!(unsafe { wi_relay_disconnect(relay, client_key.as_ptr()) });
    assert!(!unsafe { wi_relay_disconnect(relay, DENIED.as_ptr()) });
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
        wi_endpoint_free(client);
        wi_endpoint_free(server);
        wi_relay_free(relay);
    }
}

#[test]
fn a_finish_while_a_write_is_pending_finishes_nothing_and_the_write_lands_whole() {
    let link = Link::new([11, 12]);
    let ([send, recv], [peer_send, peer_recv]) = link.stream(b"x");
    let body = vec![7u8; 4 << 20];
    let write = call(|cb, cx| unsafe { wi_send_write(send, body.as_ptr(), body.len(), cb, cx) });
    assert_eq!(
        unsafe { wi_send_finish(send) },
        6,
        "ERROR while the write is pending"
    );
    let peer = peer_recv as usize;
    let reader = std::thread::spawn(move || read_to_end(peer as *mut c_void));
    ok(write);
    assert_eq!(unsafe { wi_send_finish(send) }, 0);
    assert_eq!(unsafe { wi_send_finish(send) }, 4, "CLOSED once finished");
    let received = reader.join().unwrap();
    assert_eq!(received.len(), 1 + body.len());
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
}

#[test]
fn a_read_of_at_most_zero_bytes_is_an_error_and_takes_nothing() {
    let link = Link::new([13, 14]);
    let ([send, recv], [peer_send, peer_recv]) = link.stream(b"ab");
    assert_eq!(unsafe { wi_send_finish(send) }, 0);
    assert_eq!(
        wait(call(|cb, cx| unsafe { wi_recv_read(peer_recv, 0, cb, cx) })).status,
        6
    );
    assert_eq!(read_to_end(peer_recv), b"ab");
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
}

#[test]
fn a_finish_right_after_a_reset_finishes_nothing() {
    let link = Link::new([19, 20]);
    for _ in 0..20 {
        let ([send, recv], [peer_send, peer_recv]) = link.stream(b"x");
        unsafe { wi_send_reset(send, 3) };
        assert_eq!(unsafe { wi_send_finish(send) }, 4, "CLOSED once reset");
        unsafe {
            wi_send_free(send);
            wi_recv_free(recv);
            wi_send_free(peer_send);
            wi_recv_free(peer_recv);
        }
    }
}

#[test]
fn stopped_reports_the_peers_stop_code_while_no_write_is_pending() {
    let link = Link::new([15, 16]);
    let ([send, recv], [peer_send, peer_recv]) = link.stream(b"x");
    let stopped = call(|cb, cx| unsafe { wi_send_stopped(send, cb, cx) });
    let also = call(|cb, cx| unsafe { wi_send_stopped(send, cb, cx) });
    unsafe { wi_recv_stop(peer_recv, 9) };
    for stopped in [stopped, also] {
        let stopped = wait(stopped);
        assert_eq!((stopped.status, stopped.code), (3, 9), "{stopped:?}");
    }
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
}

#[test]
fn an_empty_alpn_may_come_without_a_buffer() {
    let (relay, url) = spawn_relay();
    let secret = [17u8; 32];
    let entry = RelayEntry {
        url: url.as_ptr(),
        auth_token: ptr::null(),
    };
    let bound = wait(call(|cb, cx| unsafe {
        wi_endpoint_bind(secret.as_ptr(), &entry, 1, true, ptr::null(), 0, cb, cx)
    }));
    assert!(bound.status == 0 || bound.status == 6, "{bound:?}");
    if bound.status == 0 {
        let endpoint = bound.handles[0] as *mut c_void;
        ok(call(|cb, cx| unsafe {
            wi_endpoint_close(endpoint, cb, cx)
        }));
        unsafe { wi_endpoint_free(endpoint) };
    }
    unsafe { wi_relay_free(relay) };
}

#[test]
fn two_relay_watches_each_see_a_kick() {
    let (relay, url) = spawn_relay();
    let endpoint = bind(18, &url);
    let mut key = [0u8; 32];
    unsafe { wi_endpoint_key(endpoint, key.as_mut_ptr()) };
    assert!(eventually(Duration::from_secs(3), || unsafe {
        wi_relay_disconnect(relay, DENIED.as_ptr()) || wi_relay_disconnect(relay, key.as_ptr())
    }));
    let watches = [unsafe { wi_endpoint_watch(endpoint) }, unsafe {
        wi_endpoint_watch(endpoint)
    }];
    let next = watches.map(|watch| call(|cb, cx| unsafe { wi_watch_next(watch, cb, cx) }));
    assert!(eventually(Duration::from_secs(3), || unsafe {
        wi_relay_disconnect(relay, key.as_ptr())
    }));
    for next in next {
        ok(next);
    }
    ok(call(|cb, cx| unsafe {
        wi_endpoint_close(endpoint, cb, cx)
    }));
    for watch in watches {
        assert_eq!(
            wait(call(|cb, cx| unsafe { wi_watch_next(watch, cb, cx) })).status,
            4
        );
        unsafe { wi_watch_free(watch) };
    }
    unsafe {
        wi_endpoint_free(endpoint);
        wi_relay_free(relay);
    }
}

#[test]
fn a_relay_with_its_own_certificate_serves_https_on_its_address() {
    use std::io::{Read, Write};
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CString::new(certified.cert.pem()).unwrap();
    let key = CString::new(certified.signing_key.serialize_pem()).unwrap();
    let address = CString::new("127.0.0.1:0").unwrap();
    let access = Access {
        context: ptr::null_mut(),
        on_connect: Some(admit),
        on_disconnect: None,
        release: None,
    };
    let relay = ok(call(|cb, cx| unsafe {
        wi_relay_spawn(
            address.as_ptr(),
            cert.as_ptr(),
            key.as_ptr(),
            access,
            cb,
            cx,
        )
    }))
    .handles[0] as *mut c_void;
    let mut out = [0 as c_char; 64];
    assert!(unsafe { wi_relay_address(relay, out.as_mut_ptr(), 64) } > 0);
    let bound = unsafe { CStr::from_ptr(out.as_ptr()) }
        .to_str()
        .unwrap()
        .to_owned();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tls =
        rustls::ClientConnection::new(std::sync::Arc::new(config), "localhost".try_into().unwrap())
            .unwrap();
    let socket = std::net::TcpStream::connect(&bound).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(tls, socket);
    stream
        .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    let missing = wait(call(|cb, cx| unsafe {
        let access = Access {
            context: ptr::null_mut(),
            on_connect: None,
            on_disconnect: None,
            release: None,
        };
        wi_relay_spawn(address.as_ptr(), cert.as_ptr(), ptr::null(), access, cb, cx)
    }));
    assert_eq!(missing.status, 6, "a chain without its key is refused");
    unsafe { wi_relay_free(relay) };
}
