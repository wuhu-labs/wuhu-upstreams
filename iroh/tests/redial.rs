//! A redial through another relay while a connection to the peer still stands over a dead one.

mod common;

use std::{
    ffi::{CString, c_void},
    sync::mpsc,
    time::{Duration, Instant},
};

use common::*;

fn key_of(endpoint: *mut c_void) -> [u8; 32] {
    let mut key = [0u8; 32];
    unsafe { wi_endpoint_key(endpoint, key.as_mut_ptr()) };
    key
}

fn reported(url: &CString) -> String {
    format!("{}/", url.to_str().unwrap())
}

fn close(endpoint: *mut c_void) {
    ok(call(|cb, cx| unsafe {
        wi_endpoint_close(endpoint, cb, cx)
    }));
    unsafe { wi_endpoint_free(endpoint) };
}

/// The callback's result, failing the test once `deadline` passed without one.
fn by(deadline: Instant, receiver: mpsc::Receiver<Done>, what: &str) -> Done {
    let done = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|_| panic!("{what}: no answer by the deadline"));
    assert_eq!(done.status, 0, "{what}: {done:?}");
    done
}

/// Dials `server` through `url`, opens a stream on the new connection and reads the server's echo
/// of it, all by `deadline`. The connection stays open: its two sides come back.
fn dial_and_echo(
    client: *mut c_void,
    server: *mut c_void,
    url: &CString,
    deadline: Instant,
) -> [*mut c_void; 2] {
    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing =
        by(deadline, dial(client, &key_of(server), url), "dial").handles[0] as *mut c_void;
    let opened = by(
        deadline,
        call(|cb, cx| unsafe { wi_connection_open(outgoing, cb, cx) }),
        "open",
    );
    let (send, recv) = (
        opened.handles[0] as *mut c_void,
        opened.handles[1] as *mut c_void,
    );
    by(
        deadline,
        call(|cb, cx| unsafe { wi_send_write(send, b"ping".as_ptr(), 4, cb, cx) }),
        "write",
    );
    assert_eq!(unsafe { wi_send_finish(send) }, 0);
    let incoming = by(deadline, accepted, "accept").handles[0] as *mut c_void;
    let stream = by(
        deadline,
        call(|cb, cx| unsafe { wi_connection_accept(incoming, cb, cx) }),
        "accept stream",
    );
    let (peer_send, peer_recv) = (
        stream.handles[0] as *mut c_void,
        stream.handles[1] as *mut c_void,
    );
    assert_eq!(read_to_end(peer_recv), b"ping");
    by(
        deadline,
        call(|cb, cx| unsafe { wi_send_write(peer_send, b"pong".as_ptr(), 4, cb, cx) }),
        "echo",
    );
    assert_eq!(unsafe { wi_send_finish(peer_send) }, 0);
    assert_eq!(read_to_end(recv), b"pong");
    assert!(Instant::now() < deadline, "echo after the deadline");
    unsafe {
        wi_send_free(send);
        wi_recv_free(recv);
        wi_send_free(peer_send);
        wi_recv_free(peer_recv);
    }
    [outgoing, incoming]
}

fn free([outgoing, incoming]: [*mut c_void; 2]) {
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
    }
}

/// Both endpoints live on relay A (B sits behind a slower proxy, so A wins the reports). A dies,
/// both move home to B, and a redial through B, with the connection over A still open, echoes.
#[test]
fn a_redial_through_the_new_home_relay_beside_a_connection_over_the_dead_one_echoes_within_three_seconds()
 {
    let (relay_a, url_a) = spawn_relay();
    let (relay_b, url_b) = spawn_relay();
    let slow_b = slow_proxy(&url_b);
    let server = bind_to(60, &[(&url_a, None), (&slow_b, None)]);
    let client = bind_to(61, &[(&url_a, None), (&slow_b, None)]);
    let on = |url: &CString| {
        let url = reported(url);
        move |endpoint| connected_home(endpoint).as_ref() == Some(&url)
    };
    assert!(eventually(Duration::from_secs(3), || on(&url_a)(server)
        && on(&url_a)(client)));
    let over_a = dial_and_echo(
        client,
        server,
        &url_a,
        Instant::now() + Duration::from_secs(3),
    );

    ok(call(|cb, cx| unsafe { wi_relay_shutdown(relay_a, cb, cx) }));
    assert!(
        eventually(Duration::from_secs(5), || on(&slow_b)(server)
            && on(&slow_b)(client)),
        "both home on B"
    );
    let started = Instant::now();
    let over_b = dial_and_echo(client, server, &slow_b, started + Duration::from_secs(3));
    eprintln!("redial echoed after {:?}", started.elapsed());
    free(over_b);
    free(over_a);
    close(client);
    close(server);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// The server lives on relay A, the client on relay C. A dies and the server moves home to B; the
/// client's own relay is fine. A redial through B, with the connection over A still open, echoes.
#[test]
fn a_redial_through_the_peers_new_relay_beside_a_connection_over_its_dead_one_echoes_within_three_seconds()
 {
    let (relay_a, url_a) = spawn_relay();
    let (relay_b, url_b) = spawn_relay();
    let (relay_c, url_c) = spawn_relay();
    let slow_b = slow_proxy(&url_b);
    let server = bind_to(62, &[(&url_a, None), (&slow_b, None)]);
    let client = bind(63, &url_c);
    assert!(eventually(Duration::from_secs(3), || connected_home(
        server
    ) == Some(reported(
        &url_a
    )) && connected_home(
        client
    )
    .is_some()));
    let over_a = dial_and_echo(
        client,
        server,
        &url_a,
        Instant::now() + Duration::from_secs(3),
    );

    ok(call(|cb, cx| unsafe { wi_relay_shutdown(relay_a, cb, cx) }));
    assert!(
        eventually(Duration::from_secs(5), || connected_home(server)
            == Some(reported(&slow_b))),
        "server home on B"
    );
    let started = Instant::now();
    let over_b = dial_and_echo(client, server, &slow_b, started + Duration::from_secs(3));
    eprintln!("redial echoed after {:?}", started.elapsed());
    free(over_b);
    free(over_a);
    close(client);
    close(server);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
        wi_relay_free(relay_c);
    }
}
