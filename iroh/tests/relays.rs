//! An endpoint over several relays: tokens per relay, failover, relay states, direct addresses.

mod common;

use std::{
    ffi::{CStr, CString, c_char, c_void},
    ptr,
    sync::Mutex,
    time::{Duration, Instant},
};

use common::*;

/// What one relay's admission saw: each client key and the token it presented.
#[derive(Default)]
struct Seen(Mutex<Vec<([u8; 32], Option<String>)>>);

impl Seen {
    fn tokens(&self, key: &[u8; 32]) -> Vec<Option<String>> {
        let seen = self.0.lock().unwrap();
        seen.iter()
            .filter(|(k, _)| k == key)
            .map(|(_, t)| t.clone())
            .collect()
    }
}

unsafe extern "C" fn note(
    context: *mut c_void,
    key: *const u8,
    _: u64,
    token: *const c_char,
) -> bool {
    let seen = unsafe { &*(context as *const Seen) };
    let token = (!token.is_null()).then(|| {
        unsafe { CStr::from_ptr(token) }
            .to_string_lossy()
            .into_owned()
    });
    seen.0
        .lock()
        .unwrap()
        .push((unsafe { *(key as *const [u8; 32]) }, token));
    true
}

unsafe extern "C" fn deny(_: *mut c_void, _: *const u8, _: u64, _: *const c_char) -> bool {
    false
}

/// A relay that notes every admission in a `Seen` that lives as long as the test binary.
fn noting_relay() -> (*mut c_void, CString, &'static Seen) {
    let seen: &'static Seen = Box::leak(Box::default());
    let (relay, url) = spawn_relay_access(Access {
        context: seen as *const Seen as *mut c_void,
        on_connect: Some(note),
        on_disconnect: None,
        release: None,
    });
    (relay, url, seen)
}

fn key_of(endpoint: *mut c_void) -> [u8; 32] {
    let mut key = [0u8; 32];
    unsafe { wi_endpoint_key(endpoint, key.as_mut_ptr()) };
    key
}

fn shut_down(relay: *mut c_void) {
    ok(call(|cb, cx| unsafe { wi_relay_shutdown(relay, cb, cx) }));
}

fn close(endpoint: *mut c_void) {
    ok(call(|cb, cx| unsafe {
        wi_endpoint_close(endpoint, cb, cx)
    }));
    unsafe { wi_endpoint_free(endpoint) };
}

/// The relay URL as the endpoint reports it (iroh's form, with a trailing slash).
fn reported(url: &CString) -> String {
    format!("{}/", url.to_str().unwrap())
}

#[test]
fn each_relay_is_presented_its_own_token_and_a_relay_outside_the_map_none() {
    let (relay_a, url_a, seen_a) = noting_relay();
    let (relay_b, url_b, seen_b) = noting_relay();
    let token_a = CString::new("token-for-a").unwrap();
    let token_b = CString::new("token-for-b").unwrap();
    let server = bind_to(31, &[(&url_b, Some(&token_b))]);
    let client = bind_to(32, &[(&url_a, Some(&token_a))]);
    let (server_key, client_key) = (key_of(server), key_of(client));
    assert!(eventually(Duration::from_secs(3), || {
        connected_home(server).is_some() && connected_home(client).is_some()
    }));

    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing = ok(dial(client, &server_key, &url_b)).handles[0] as *mut c_void;
    let incoming = ok(accepted).handles[0] as *mut c_void;

    assert_eq!(
        seen_a.tokens(&client_key),
        vec![Some("token-for-a".to_string())]
    );
    assert_eq!(
        seen_b.tokens(&server_key),
        vec![Some("token-for-b".to_string())]
    );
    assert_eq!(
        seen_b.tokens(&client_key),
        vec![None],
        "the client reached the server's relay, outside its map, with no token"
    );
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
    }
    close(client);
    close(server);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

#[test]
fn a_replaced_token_is_presented_on_the_next_connection_and_leaves_the_live_one_alone() {
    let (relay, url, seen) = noting_relay();
    let first = CString::new("first").unwrap();
    let endpoint = bind_to(33, &[(&url, Some(&first))]);
    let key = key_of(endpoint);
    assert!(eventually(Duration::from_secs(3), || connected_home(
        endpoint
    )
    .is_some()));
    assert_eq!(seen.tokens(&key), vec![Some("first".to_string())]);

    let second = CString::new("second").unwrap();
    ok(call(|cb, cx| unsafe {
        wi_endpoint_set_auth_token(endpoint, url.as_ptr(), second.as_ptr(), cb, cx)
    }));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        seen.tokens(&key).len(),
        1,
        "the live connection is not redialled"
    );
    assert!(connected_home(endpoint).is_some());

    assert!(unsafe { wi_relay_disconnect(relay, key.as_ptr()) });
    assert!(eventually(Duration::from_secs(3), || seen
        .tokens(&key)
        .len()
        == 2));
    assert_eq!(seen.tokens(&key)[1], Some("second".to_string()));

    ok(call(|cb, cx| unsafe {
        wi_endpoint_set_auth_token(endpoint, url.as_ptr(), ptr::null(), cb, cx)
    }));
    assert!(eventually(Duration::from_secs(3), || unsafe {
        wi_relay_disconnect(relay, key.as_ptr())
    }));
    assert!(eventually(Duration::from_secs(3), || seen
        .tokens(&key)
        .len()
        == 3));
    assert_eq!(
        seen.tokens(&key)[2],
        None,
        "a removed token is not presented"
    );

    let elsewhere = CString::new("http://127.0.0.1:9").unwrap();
    let refused = wait(call(|cb, cx| unsafe {
        wi_endpoint_set_auth_token(endpoint, elsewhere.as_ptr(), second.as_ptr(), cb, cx)
    }));
    assert_eq!(refused.status, 6, "{refused:?}");
    assert!(
        refused.message.contains("not in the endpoint's map"),
        "{refused:?}"
    );
    close(endpoint);
    unsafe { wi_relay_free(relay) };
}

#[test]
fn the_home_relay_fails_over_to_another_relay_of_the_map_within_five_seconds() {
    let (relay_a, url_a) = spawn_relay();
    let (relay_b, url_b) = spawn_relay();
    let endpoint = bind_to(34, &[(&url_a, None), (&url_b, None)]);
    assert!(eventually(Duration::from_secs(3), || connected_home(
        endpoint
    )
    .is_some()));
    let home = connected_home(endpoint).unwrap();
    let (dead, other) = if home == reported(&url_a) {
        (relay_a, reported(&url_b))
    } else {
        (relay_b, reported(&url_a))
    };
    let states = relays(endpoint);
    assert_eq!(states.len(), 2);
    let probed = states.iter().find(|state| state.url() == other).unwrap();
    assert!(
        !is_home(probed.kind),
        "only the home relay reads as connected"
    );

    let started = Instant::now();
    shut_down(dead);
    assert!(
        eventually(Duration::from_secs(5), || connected_home(endpoint).as_ref()
            == Some(&other)),
        "home still {:?} after 5 s",
        connected_home(endpoint)
    );
    eprintln!("failover took {:?}", started.elapsed());
    let states = relays(endpoint);
    let old = states.iter().find(|state| state.url() == home).unwrap();
    assert!(!is_home(old.kind));
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

#[test]
fn with_every_relay_down_the_endpoint_runs_no_report_loop() {
    let (relay_a, url_a) = spawn_relay();
    let (relay_b, url_b) = spawn_relay();
    let endpoint = bind_to(35, &[(&url_a, None), (&url_b, None)]);
    assert!(eventually(Duration::from_secs(3), || connected_home(
        endpoint
    )
    .is_some()));
    let home = connected_home(endpoint).unwrap();
    shut_down(relay_a);
    shut_down(relay_b);
    let before = unsafe { wuhu_iroh::net_reports(endpoint) };
    std::thread::sleep(Duration::from_secs(4));
    let reports = unsafe { wuhu_iroh::net_reports(endpoint) } - before;
    eprintln!("{reports} net reports in 4 s with every relay down");
    // Failovers at 0, 0.5, 1.5 and 3.5 s at most, beside the reports at bind.
    assert!(reports <= 12, "{reports} net reports in 4 s");
    let states = relays(endpoint);
    let stayed = states
        .iter()
        .find(|state| is_home(state.kind))
        .expect("a home relay");
    assert_eq!(
        stayed.url(),
        home,
        "with nowhere better to go the home stays"
    );
    assert_ne!(stayed.kind, HOME_CONNECTED);
    assert!(!stayed.last_error().is_empty());
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// The home relay refuses the endpoint for a while, so its redials fail and each runs a net report,
/// while its probes still answer: once it admits the endpoint again, the endpoint is back on it,
/// not moved to the slower relay. The failure itself picks no relay; the report does.
#[test]
fn a_home_relay_that_comes_back_first_keeps_the_endpoint() {
    let (relay_a, url_a) = spawn_relay_with(admit_unless_shut_out, record_gone);
    let (relay_b, direct_b) = spawn_relay();
    let url_b = slow_proxy(&direct_b);
    let endpoint = bind_to(36, &[(&url_a, None), (&url_b, None)]);
    assert!(eventually(Duration::from_secs(3), || connected_home(
        endpoint
    )
    .is_some()));
    assert_eq!(
        connected_home(endpoint),
        Some(reported(&url_a)),
        "the nearer relay is home"
    );
    let key = key_of(endpoint);
    let before = unsafe { wuhu_iroh::net_reports(endpoint) };
    SHUT_OUT.lock().unwrap().push(key);
    assert!(unsafe { wi_relay_disconnect(relay_a, key.as_ptr()) });
    assert!(
        eventually(Duration::from_secs(3), || unsafe {
            wuhu_iroh::net_reports(endpoint)
        } > before),
        "a failed redial runs a report"
    );
    SHUT_OUT.lock().unwrap().retain(|k| *k != key);
    assert!(
        eventually(Duration::from_secs(3), || connected_home(endpoint)
            .is_some()),
        "connected again"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        connected_home(endpoint),
        Some(reported(&url_a)),
        "no forced move off a relay that came back"
    );
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

#[test]
fn a_relay_that_refuses_the_endpoint_is_redialled_with_backoff_only_and_each_redial_names_the_failure()
 {
    let (relay, url) = spawn_relay_access(Access {
        context: ptr::null_mut(),
        on_connect: Some(deny),
        on_disconnect: None,
        release: None,
    });
    let endpoint = bind(37, &url);
    let before = unsafe { wuhu_iroh::net_reports(endpoint) };
    let started = Instant::now();
    let (mut failed, mut redialling) = (false, 0);
    while started.elapsed() < Duration::from_secs(3) {
        let state = &relays(endpoint)[0];
        let error = state.last_error();
        match state.kind {
            HOME_DISCONNECTED => {
                assert!(!error.is_empty(), "disconnected without an error");
                failed = true;
            }
            HOME_CONNECTING if failed => {
                assert!(!error.is_empty(), "a redial forgot the failure");
                redialling += 1;
            }
            HOME_CONNECTING => assert!(error.is_empty(), "{error}"),
            HOME_CONNECTED => panic!("connected to a relay that refuses"),
            _ => assert!(!failed, "no longer home after a failure"),
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    let reports = unsafe { wuhu_iroh::net_reports(endpoint) } - before;
    eprintln!("{reports} net reports in 3 s while refused, {redialling} samples redialling");
    assert!(reports <= 12, "{reports} net reports in 3 s");
    assert!(failed && redialling > 0);
    close(endpoint);
    unsafe { wi_relay_free(relay) };
}

#[test]
fn direct_addresses_are_dialable_ones_and_a_dial_by_address_alone_connects() {
    let (relay, url) = spawn_relay();
    let alpn = b"wuhu/test/0";
    let entry = RelayEntry {
        url: url.as_ptr(),
        auth_token: ptr::null(),
    };
    let bind_direct = |seed: u8| {
        let secret = [seed; 32];
        ok(call(|cb, cx| unsafe {
            wi_endpoint_bind(
                secret.as_ptr(),
                &entry,
                1,
                false,
                alpn.as_ptr(),
                alpn.len(),
                cb,
                cx,
            )
        }))
        .handles[0] as *mut c_void
    };
    let server = bind_direct(38);
    let client = bind_direct(39);
    let read = |endpoint| {
        let len = unsafe { wi_endpoint_direct_addresses(endpoint, ptr::null_mut(), 0) };
        let mut out = vec![0 as c_char; len + 1];
        assert_eq!(
            unsafe { wi_endpoint_direct_addresses(endpoint, out.as_mut_ptr(), out.len()) },
            len
        );
        unsafe { CStr::from_ptr(out.as_ptr()) }
            .to_str()
            .unwrap()
            .to_string()
    };
    assert!(eventually(Duration::from_secs(3), || !read(server).is_empty()));
    let text = read(server);
    let addresses: Vec<std::net::SocketAddr> =
        text.lines().map(|line| line.parse().unwrap()).collect();
    for address in &addresses {
        assert!(
            !address.ip().is_loopback() && !address.ip().is_unspecified(),
            "{text}"
        );
        if let std::net::IpAddr::V6(ip) = address.ip() {
            assert_eq!(ip.segments()[0] & 0xe000, 0x2000, "{text}");
        }
    }
    assert!(text.ends_with('\n'));

    let wanted: Vec<CString> = addresses
        .iter()
        .map(|a| CString::new(a.to_string()).unwrap())
        .collect();
    let pointers: Vec<*const c_char> = wanted.iter().map(|a| a.as_ptr()).collect();
    let server_key = key_of(server);
    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing = ok(call(|cb, cx| unsafe {
        wi_endpoint_connect(
            client,
            server_key.as_ptr(),
            ptr::null(),
            pointers.as_ptr(),
            pointers.len(),
            cb,
            cx,
        )
    }))
    .handles[0] as *mut c_void;
    let incoming = ok(accepted).handles[0] as *mut c_void;

    let nothing = wait(call(|cb, cx| unsafe {
        wi_endpoint_connect(
            client,
            server_key.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            cb,
            cx,
        )
    }));
    assert_eq!(nothing.status, 6, "{nothing:?}");
    let bad = c"not-an-address".as_ptr();
    let unparsable = wait(call(|cb, cx| unsafe {
        wi_endpoint_connect(client, server_key.as_ptr(), ptr::null(), &bad, 1, cb, cx)
    }));
    assert_eq!(unparsable.status, 6, "{unparsable:?}");
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
    }
    close(client);
    close(server);
    unsafe { wi_relay_free(relay) };
}

#[test]
fn relays_that_refuse_every_dial_start_failovers_at_a_doubling_gap_only() {
    let refusing = || {
        spawn_relay_access(Access {
            context: ptr::null_mut(),
            on_connect: Some(deny),
            on_disconnect: None,
            release: None,
        })
    };
    let (relay_a, url_a) = refusing();
    let (relay_b, url_b) = refusing();
    let endpoint = bind_to(41, &[(&url_a, None), (&url_b, None)]);
    std::thread::sleep(Duration::from_secs(4));
    let failovers = unsafe { wuhu_iroh::failovers(endpoint) };
    let reports = unsafe { wuhu_iroh::net_reports(endpoint) };
    eprintln!("{failovers} failovers and {reports} net reports in 4 s, every dial refused");
    // Gaps of 0.5, 1 and 2 s after the first: four by 3.5 s, however often iroh redials.
    assert!((2..=4).contains(&failovers), "{failovers} failovers in 4 s");
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}
