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
    dial_and_echo_beside(client, server, url, None, deadline).0
}

/// `dial_and_echo`, with a dial of the same peer through `beside` started right after this
/// dial: that dial's answer comes back unread, with the connection.
fn dial_and_echo_beside(
    client: *mut c_void,
    server: *mut c_void,
    url: &CString,
    beside: Option<&CString>,
    deadline: Instant,
) -> ([*mut c_void; 2], Option<mpsc::Receiver<Done>>) {
    // With a dial beside, both dials' packets reach the server through B (every recent dial's
    // addresses get them), and either may be accepted first: the server accepts both, and the
    // stream tells which one is this dial's.
    let accepts: Vec<_> = (0..if beside.is_some() { 2 } else { 1 })
        .map(|_| call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) }))
        .collect();
    let dialled = dial(client, &key_of(server), url);
    let other = beside.map(|beside| dial(client, &key_of(server), beside));
    let outgoing = by(deadline, dialled, "dial").handles[0] as *mut c_void;
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
    let (incoming, stream) = accept_stream(accepts, deadline);
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
    ([outgoing, incoming], other)
}

/// The connection, among those `accepts` yield, that a stream comes in on first, and the
/// stream, by `deadline`. The others are freed.
fn accept_stream(accepts: Vec<mpsc::Receiver<Done>>, deadline: Instant) -> (*mut c_void, Done) {
    let mut accepts: Vec<Option<mpsc::Receiver<Done>>> = accepts.into_iter().map(Some).collect();
    let mut streams: Vec<(*mut c_void, mpsc::Receiver<Done>)> = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "accept stream: no stream by the deadline"
        );
        for slot in &mut accepts {
            if let Some(done) = slot.as_ref().and_then(|accept| accept.try_recv().ok()) {
                *slot = None;
                assert_eq!(done.status, 0, "accept: {done:?}");
                let incoming = done.handles[0] as *mut c_void;
                streams.push((
                    incoming,
                    call(|cb, cx| unsafe { wi_connection_accept(incoming, cb, cx) }),
                ));
            }
        }
        for n in 0..streams.len() {
            if let Ok(stream) = streams[n].1.try_recv() {
                assert_eq!(stream.status, 0, "accept stream: {stream:?}");
                let (incoming, _) = streams.swap_remove(n);
                for (other, _) in streams {
                    unsafe { wi_connection_free(other) };
                }
                return (incoming, stream);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The answer of `wi_connection_closed` on `connection`, once it comes.
fn closed(connection: *mut c_void) -> mpsc::Receiver<Done> {
    call(|cb, cx| unsafe { wi_connection_closed(connection, cb, cx) })
}

/// Both endpoints home on A (B behind a slower proxy, so A wins the reports), with a
/// connection over A that echoed; then A shut down and both home on B.
fn over_a_then_home_on_b(
    seeds: [u8; 2],
) -> (
    *mut c_void,
    *mut c_void,
    [*mut c_void; 2],
    [*mut c_void; 2],
    CString,
    CString,
) {
    let (relay_a, url_a) = spawn_relay();
    let (relay_b, url_b) = spawn_relay();
    let slow_b = slow_proxy(&url_b);
    let server = bind_to(seeds[0], &[(&url_a, None), (&slow_b, None)]);
    let client = bind_to(seeds[1], &[(&url_a, None), (&slow_b, None)]);
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
    (server, client, over_a, [relay_a, relay_b], url_a, slow_b)
}

fn free([outgoing, incoming]: [*mut c_void; 2]) {
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
    }
}

/// Both endpoints live on relay A (B sits behind a slower proxy, so A wins the reports). A dies,
/// both move home to B, and a redial through B, with the connection over A still open, echoes.
/// The connection over A stays open beside it (closing it is the caller's choice), and the new
/// one runs over relay B.
#[test]
fn a_redial_through_the_new_home_relay_beside_a_connection_over_the_dead_one_echoes_within_three_seconds()
 {
    let (server, client, over_a, relays, _, slow_b) = over_a_then_home_on_b([60, 61]);
    let over_a_closed = [closed(over_a[0]), closed(over_a[1])];
    let started = Instant::now();
    let over_b = dial_and_echo(client, server, &slow_b, started + Duration::from_secs(3));
    eprintln!("redial echoed after {:?}", started.elapsed());
    for (side, closed) in ["client", "server"].iter().zip(&over_a_closed) {
        assert!(
            matches!(closed.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "the {side}'s connection over A closed when the redial succeeded"
        );
    }
    assert_eq!(path(over_b[0]), Some((true, reported(&slow_b))));
    assert_eq!(path(over_b[1]).map(|(relay, _)| relay), Some(true));
    free(over_b);
    free(over_a);
    close(client);
    close(server);
    unsafe {
        wi_relay_free(relays[0]);
        wi_relay_free(relays[1]);
    }
}

/// As above, with a second dial of the same peer through the dead relay A started right after
/// the dial through B: the dial through B still echoes within 3 s, its handshake's packets are
/// not moved to the newer dial's dead relay.
#[test]
fn a_redial_through_the_new_home_relay_echoes_beside_a_concurrent_dial_through_the_dead_one() {
    let (server, client, over_a, relays, url_a, slow_b) = over_a_then_home_on_b([64, 65]);
    let started = Instant::now();
    let (over_b, through_a) = dial_and_echo_beside(
        client,
        server,
        &slow_b,
        Some(&url_a),
        started + Duration::from_secs(3),
    );
    eprintln!("redial echoed after {:?}", started.elapsed());
    free(over_b);
    free(over_a);
    close(client);
    close(server);
    drop(through_a);
    unsafe {
        wi_relay_free(relays[0]);
        wi_relay_free(relays[1]);
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
    let over_a_closed = closed(over_a[0]);
    let over_b = dial_and_echo(client, server, &slow_b, started + Duration::from_secs(3));
    eprintln!("redial echoed after {:?}", started.elapsed());
    assert!(
        matches!(over_a_closed.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "the connection over A closed when the redial succeeded"
    );
    assert_eq!(path(over_b[0]), Some((true, reported(&slow_b))));
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
