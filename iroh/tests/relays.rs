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

/// A relay's admission rule over a client's key and token; every admission is noted in `seen`.
struct Door {
    seen: Seen,
    admits: fn(&[u8; 32], Option<&str>) -> bool,
}

unsafe extern "C" fn knock(
    context: *mut c_void,
    key: *const u8,
    _: u64,
    token: *const c_char,
) -> bool {
    let door = unsafe { &*(context as *const Door) };
    let token = (!token.is_null()).then(|| {
        unsafe { CStr::from_ptr(token) }
            .to_string_lossy()
            .into_owned()
    });
    let key = unsafe { *(key as *const [u8; 32]) };
    door.seen.0.lock().unwrap().push((key, token.clone()));
    (door.admits)(&key, token.as_deref())
}

/// A relay that admits whom `admits` lets in and notes every admission.
fn door_relay(
    admits: fn(&[u8; 32], Option<&str>) -> bool,
) -> (*mut c_void, CString, &'static Seen) {
    let door: &'static Door = Box::leak(Box::new(Door {
        seen: Seen::default(),
        admits,
    }));
    let (relay, url) = spawn_relay_access(Access {
        context: door as *const Door as *mut c_void,
        on_connect: Some(knock),
        on_disconnect: None,
        release: None,
    });
    (relay, url, &door.seen)
}

fn public_key(seed: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    unsafe { wi_secret_key_public([seed; 32].as_ptr(), key.as_mut_ptr()) };
    key
}

fn state_of(endpoint: *mut c_void, url: &CString) -> RelayState {
    relays(endpoint)
        .into_iter()
        .find(|state| state.url() == reported(url))
        .expect("a relay of the map")
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
            // A redial can start before a sample sees the failure itself.
            HOME_CONNECTING if failed || !error.is_empty() => {
                assert!(!error.is_empty(), "a redial forgot the failure");
                failed = true;
                redialling += 1;
            }
            HOME_CONNECTING => {}
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

/// Both relays answer every probe and refuse every connection. iroh redials each with its
/// backoff, but runs a report only for a relay's first failure since it last connected: no
/// report per failed dial. With only failing relays reached, the one home longest ago is home, so
/// the home moves off the first relay to fail and back to it once the other has failed too.
#[test]
fn relays_that_refuse_every_dial_run_a_report_per_first_failure_only_and_trade_home() {
    let (relay_a, url_a, seen_a) = door_relay(|_, _| false);
    let (relay_b, url_b, seen_b) = door_relay(|_, _| false);
    let endpoint = bind_to(41, &[(&url_a, None), (&url_b, None)]);
    let key = key_of(endpoint);
    let mut homes: Vec<String> = Vec::new();
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until {
        if let Some(home) = relays(endpoint).into_iter().find(|s| is_home(s.kind)) {
            if homes.last() != Some(&home.url()) {
                homes.push(home.url());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let reports = unsafe { wuhu_iroh::net_reports(endpoint) };
    let dials = seen_a.tokens(&key).len() + seen_b.tokens(&key).len();
    eprintln!("{reports} net reports and {dials} refused dials in 8 s; homes {homes:?}");
    // The bind's reports, then one per relay's first failure.
    assert!(reports <= 6, "{reports} net reports in 8 s");
    assert!(dials > reports as usize, "{dials} refused dials");
    assert!(
        homes.len() >= 3,
        "the home went A, B, A (or B, A, B): {homes:?}"
    );
    assert_eq!(homes[0], homes[2], "{homes:?}");
    for state in relays(endpoint) {
        if is_home(state.kind) {
            assert_ne!(state.kind, HOME_CONNECTED, "{state:?}");
        } else {
            assert_eq!(state.kind, FAILED, "{state:?}");
            assert!(!state.last_error().is_empty(), "{state:?}");
        }
    }
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// The nearer relay answers every probe and refuses every connection, for good. The endpoint
/// leaves it for the relay that admits it within one report of its first failure, and stays
/// there through later full reports, in which the refusing relay answers its probe again.
#[test]
fn a_home_relay_that_answers_probes_but_refuses_every_connection_loses_home_to_one_that_admits_and_for_good()
 {
    let (relay_a, url_a) = spawn_relay_access(Access {
        context: ptr::null_mut(),
        on_connect: Some(deny),
        on_disconnect: None,
        release: None,
    });
    let (relay_b, direct_b) = spawn_relay();
    let url_b = slow_proxy(&direct_b);
    let started = Instant::now();
    let endpoint = bind_to(42, &[(&url_a, None), (&url_b, None)]);
    assert!(
        eventually(Duration::from_secs(3), || connected_home(endpoint)
            == Some(reported(&url_b))),
        "home {:?} after 3 s: {:?}",
        connected_home(endpoint),
        relays(endpoint)
    );
    eprintln!("home on B after {:?}", started.elapsed());
    let a = state_of(endpoint, &url_a);
    assert_eq!(a.kind, FAILED, "{a:?}");
    assert!(!a.last_error().is_empty(), "{a:?}");

    for _ in 0..3 {
        // Returns once a full report with a probe of A was published.
        unsafe { wuhu_iroh::run_net_report(endpoint, url_a.to_str().unwrap()) };
        let until = Instant::now() + Duration::from_millis(700);
        while Instant::now() < until {
            assert_eq!(
                connected_home(endpoint),
                Some(reported(&url_b)),
                "{:?}",
                relays(endpoint)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let a = state_of(endpoint, &url_a);
        assert_eq!(a.kind, FAILED, "{a:?}");
    }
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// A relay that refused the endpoint and admits it again is home again once the other goes
/// down, and stays home through a later report.
#[test]
fn a_failed_relay_that_admits_again_is_home_again_when_the_other_goes_down() {
    let (relay_a, url_a) = spawn_relay_with(admit_unless_shut_out, record_gone);
    let (relay_b, direct_b) = spawn_relay();
    let url_b = slow_proxy(&direct_b);
    let key = public_key(43);
    SHUT_OUT.lock().unwrap().push(key);
    let endpoint = bind_to(43, &[(&url_a, None), (&url_b, None)]);
    assert!(
        eventually(Duration::from_secs(3), || connected_home(endpoint)
            == Some(reported(&url_b))),
        "home {:?}: {:?}",
        connected_home(endpoint),
        relays(endpoint)
    );
    SHUT_OUT.lock().unwrap().retain(|k| *k != key);
    shut_down(relay_b);
    assert!(
        eventually(Duration::from_secs(6), || connected_home(endpoint)
            == Some(reported(&url_a))),
        "home {:?}: {:?}",
        connected_home(endpoint),
        relays(endpoint)
    );
    unsafe { wuhu_iroh::run_net_report(endpoint, url_a.to_str().unwrap()) };
    let until = Instant::now() + Duration::from_secs(1);
    while Instant::now() < until {
        assert_eq!(connected_home(endpoint), Some(reported(&url_a)));
        std::thread::sleep(Duration::from_millis(20));
    }
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

#[test]
fn a_token_change_on_a_closed_endpoint_reports_closed() {
    let (relay, url) = spawn_relay();
    let endpoint = bind_to(46, &[(&url, None)]);
    ok(call(|cb, cx| unsafe {
        wi_endpoint_close(endpoint, cb, cx)
    }));
    let token = CString::new("late").unwrap();
    let changed = wait(call(|cb, cx| unsafe {
        wi_endpoint_set_auth_token(endpoint, url.as_ptr(), token.as_ptr(), cb, cx)
    }));
    assert_eq!(changed.status, 4, "CLOSED: {changed:?}");
    unsafe {
        wi_endpoint_free(endpoint);
        wi_relay_free(relay);
    }
}

/// Relay URLs past 255 bytes, two of them alike in their first 300, come back whole from the
/// relay states and from a connection's path.
#[test]
fn relay_urls_longer_than_255_bytes_come_back_whole() {
    let (relay, url) = spawn_relay();
    let long = |tail: &str| {
        let url = url.to_str().unwrap();
        let (scheme, rest) = url.split_once("://").unwrap();
        CString::new(format!("{scheme}://{}{tail}@{rest}", "x".repeat(300))).unwrap()
    };
    let (one, two) = (long("1"), long("2"));
    let client = bind_to(47, &[(&one, None), (&two, None)]);
    let urls: Vec<String> = relays(client).iter().map(|state| state.url()).collect();
    let wanted: Vec<String> = [&one, &two].iter().map(|url| reported(url)).collect();
    assert_eq!(urls, wanted, "iroh's form: a trailing slash");

    let server = bind_to(48, &[(&one, None)]);
    assert!(eventually(Duration::from_secs(3), || connected_home(
        server
    )
    .is_some()
        && connected_home(client).is_some()));
    assert_eq!(connected_home(server), Some(wanted[0].clone()));
    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(server, cb, cx) });
    let outgoing = ok(dial(client, &key_of(server), &one)).handles[0] as *mut c_void;
    let incoming = ok(accepted).handles[0] as *mut c_void;
    assert_eq!(path(outgoing), Some((true, wanted[0].clone())));
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
    }
    close(client);
    close(server);
    unsafe { wi_relay_free(relay) };
}

fn good_token_only(_: &[u8; 32], token: Option<&str>) -> bool {
    token == Some("good")
}

/// A relay that refused the endpoint admits it again while the endpoint stays home on the other:
/// its next redial connects, which ends its failure. Nothing else changes (no report, the same
/// home), and the states watch fires all the same.
#[test]
fn a_failed_relay_that_connects_again_wakes_the_states_watch_with_no_report_or_home_change() {
    let (relay_a, url_a) = spawn_relay_with(admit_unless_shut_out, record_gone);
    let (relay_b, direct_b) = spawn_relay();
    let url_b = slow_proxy(&direct_b);
    let key = public_key(44);
    SHUT_OUT.lock().unwrap().push(key);
    let endpoint = bind_to(44, &[(&url_a, None), (&url_b, None)]);
    assert!(
        eventually(Duration::from_secs(3), || connected_home(endpoint)
            == Some(reported(&url_b))),
        "home {:?}: {:?}",
        connected_home(endpoint),
        relays(endpoint)
    );
    assert_eq!(state_of(endpoint, &url_a).kind, FAILED);
    std::thread::sleep(Duration::from_millis(300));

    let watch = unsafe { wi_endpoint_watch(endpoint) };
    let reports = unsafe { wuhu_iroh::net_reports(endpoint) };
    SHUT_OUT.lock().unwrap().retain(|k| *k != key);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let next = call(|cb, cx| unsafe { wi_watch_next(watch, cb, cx) });
        let fired = next
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("no states change in 5 s: {:?}", relays(endpoint)));
        assert_eq!(fired.status, 0, "{fired:?}");
        if state_of(endpoint, &url_a).kind != FAILED {
            break;
        }
    }
    assert_eq!(connected_home(endpoint), Some(reported(&url_b)));
    assert_eq!(
        unsafe { wuhu_iroh::net_reports(endpoint) },
        reports,
        "no report ran"
    );
    unsafe { wi_watch_free(watch) };
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// A relay that refused the endpoint's token gets a new token; a dial naming that relay goes
/// out at once, not after the relay's redial backoff, and presents the new token.
#[test]
fn a_dial_naming_a_failed_relay_connects_at_once_with_its_current_token() {
    let (relay_a, url_a, seen_a) = door_relay(good_token_only);
    let (relay_b, direct_b) = spawn_relay();
    let url_b = slow_proxy(&direct_b);
    let (bad, good) = (CString::new("bad").unwrap(), CString::new("good").unwrap());
    let peer = bind_to(49, &[(&url_a, Some(&good))]);
    let endpoint = bind_to(50, &[(&url_a, Some(&bad)), (&url_b, None)]);
    let key = key_of(endpoint);
    assert!(
        eventually(Duration::from_secs(6), || connected_home(endpoint)
            == Some(reported(&url_b))
            && connected_home(peer) == Some(reported(&url_a))),
        "{:?}",
        relays(endpoint)
    );
    assert_eq!(state_of(endpoint, &url_a).kind, FAILED);
    // iroh doubles A's redial delay from 10 ms at each refusal: after the ninth it waits 2.56 s
    // or more, longer than the dial's bound.
    assert!(
        eventually(Duration::from_secs(10), || seen_a.tokens(&key).len() >= 9),
        "{} refusals",
        seen_a.tokens(&key).len()
    );

    ok(call(|cb, cx| unsafe {
        wi_endpoint_set_auth_token(endpoint, url_a.as_ptr(), good.as_ptr(), cb, cx)
    }));
    assert_eq!(
        state_of(endpoint, &url_a).kind,
        FAILED,
        "a token change alone connects nothing"
    );

    let accepted = call(|cb, cx| unsafe { wi_endpoint_accept(peer, cb, cx) });
    let started = std::time::Instant::now();
    let outgoing = ok(dial(endpoint, &key_of(peer), &url_a)).handles[0] as *mut c_void;
    let incoming = ok(accepted).handles[0] as *mut c_void;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the dial took {:?}",
        started.elapsed()
    );
    assert!(
        eventually(Duration::from_secs(1), || state_of(endpoint, &url_a).kind
            != FAILED),
        "the dial's connection to A ended its failure"
    );
    assert_eq!(
        seen_a.tokens(&key).last().cloned().flatten().as_deref(),
        Some("good"),
        "{:?}",
        seen_a.tokens(&key)
    );
    unsafe {
        wi_connection_free(outgoing);
        wi_connection_free(incoming);
    }
    close(endpoint);
    close(peer);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// Every interface address of this host.
fn interface_ips() -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    let mut list: *mut libc::ifaddrs = ptr::null_mut();
    assert_eq!(unsafe { libc::getifaddrs(&mut list) }, 0);
    let mut next = list;
    while !next.is_null() {
        let entry = unsafe { &*next };
        if !entry.ifa_addr.is_null() {
            match unsafe { (*entry.ifa_addr).sa_family } as i32 {
                libc::AF_INET => {
                    let addr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                    ips.push(std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)).into());
                }
                libc::AF_INET6 => {
                    let addr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                    ips.push(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr).into());
                }
                _ => {}
            }
        }
        next = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(list) };
    ips
}

/// Every direct address an endpoint advertises is one of this host's interface addresses: no
/// address a relay observed (QUIC address discovery is off) and none a router mapped (port
/// mapping is off).
#[test]
fn direct_addresses_are_this_hosts_interface_addresses_only() {
    let (relay, url) = spawn_relay();
    let alpn = b"wuhu/test/0";
    let entry = RelayEntry {
        url: url.as_ptr(),
        auth_token: ptr::null(),
    };
    let secret = [51u8; 32];
    let endpoint = ok(call(|cb, cx| unsafe {
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
    .handles[0] as *mut c_void;
    assert!(eventually(Duration::from_secs(3), || connected_home(
        endpoint
    )
    .is_some()));
    std::thread::sleep(Duration::from_secs(1));
    let len = unsafe { wi_endpoint_direct_addresses(endpoint, ptr::null_mut(), 0) };
    let mut out = vec![0 as c_char; len + 1];
    unsafe { wi_endpoint_direct_addresses(endpoint, out.as_mut_ptr(), out.len()) };
    let text = unsafe { CStr::from_ptr(out.as_ptr()) }
        .to_str()
        .unwrap()
        .to_string();
    let local = interface_ips();
    for line in text.lines() {
        let address: std::net::SocketAddr = line.parse().unwrap();
        assert!(
            local.contains(&address.ip()),
            "{address} is no interface address: {local:?}"
        );
    }
    close(endpoint);
    unsafe { wi_relay_free(relay) };
}

/// A relay behind a TCP forwarder that counts relay upgrade requests and, while `hold` is
/// set, keeps each one 2 s before it forwards it: the client's upgrade is in flight all that
/// time. The relay refuses every client while `refuse` is set.
#[derive(Default)]
struct Holding {
    hold: std::sync::atomic::AtomicBool,
    refuse: std::sync::atomic::AtomicBool,
    upgrades: std::sync::atomic::AtomicUsize,
}

impl Holding {
    fn set(flag: &std::sync::atomic::AtomicBool, on: bool) {
        flag.store(on, std::sync::atomic::Ordering::SeqCst)
    }

    fn upgrades(&self) -> usize {
        self.upgrades.load(std::sync::atomic::Ordering::SeqCst)
    }
}

unsafe extern "C" fn admit_unless_refusing(
    context: *mut c_void,
    _: *const u8,
    _: u64,
    _: *const c_char,
) -> bool {
    let holding = unsafe { &*(context as *const Holding) };
    !holding.refuse.load(std::sync::atomic::Ordering::SeqCst)
}

fn holding_relay() -> (*mut c_void, CString, &'static Holding) {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        sync::atomic::Ordering,
    };
    let holding: &'static Holding = Box::leak(Box::default());
    let (relay, direct) = spawn_relay_access(Access {
        context: holding as *const Holding as *mut c_void,
        on_connect: Some(admit_unless_refusing),
        on_disconnect: None,
        release: None,
    });
    let target = direct
        .to_str()
        .unwrap()
        .trim_start_matches("http://")
        .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = CString::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    std::thread::spawn(move || {
        for mut client in listener.incoming().flatten() {
            let target = target.clone();
            std::thread::spawn(move || {
                // Slower than a relay reached directly, so a relay beside it probes nearer.
                std::thread::sleep(Duration::from_millis(40));
                let mut first = vec![0u8; 4096];
                let Ok(n) = client.read(&mut first) else {
                    return;
                };
                first.truncate(n);
                if first.windows(7).any(|w| w == b" /relay") {
                    holding.upgrades.fetch_add(1, Ordering::SeqCst);
                    if holding.hold.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
                let Ok(mut server) = TcpStream::connect(&target) else {
                    return;
                };
                if server.write_all(&first).is_err() {
                    return;
                }
                let (mut c, mut s) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c, &mut s);
                    let _ = s.shutdown(Shutdown::Write);
                });
                let _ = std::io::copy(&mut server, &mut client);
                let _ = client.shutdown(Shutdown::Write);
            });
        }
    });
    (relay, url, holding)
}

/// Starts a dial of `key` through `url` naming `addresses`; the operation, for `wi_cancel`.
fn dial_naming(
    endpoint: *mut c_void,
    key: &[u8; 32],
    url: &CString,
    addresses: &[CString],
) -> (u64, std::sync::mpsc::Receiver<Done>) {
    let pointers: Vec<*const c_char> = addresses.iter().map(|a| a.as_ptr()).collect();
    let mut operation = 0;
    let done = call(|cb, cx| {
        operation = unsafe {
            wi_endpoint_connect(
                endpoint,
                key.as_ptr(),
                url.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                cb,
                cx,
            )
        };
        operation
    });
    (operation, done)
}

/// The endpoint is home on B and redials B after B dropped it; B holds that upgrade 2 s. A dial
/// naming failed A meanwhile retries A only: B's upgrade in flight completes, the only one sent.
#[test]
fn a_dial_naming_a_failed_relay_leaves_another_relays_upgrade_in_flight_alone() {
    let (relay_a, url_a) = spawn_relay_access(Access {
        context: ptr::null_mut(),
        on_connect: Some(deny),
        on_disconnect: None,
        release: None,
    });
    let (relay_b, url_b, holding) = holding_relay();
    let endpoint = bind_to(52, &[(&url_a, None), (&url_b, None)]);
    let key = key_of(endpoint);
    assert!(
        eventually(Duration::from_secs(3), || connected_home(endpoint)
            == Some(reported(&url_b))),
        "{:?}",
        relays(endpoint)
    );
    assert_eq!(state_of(endpoint, &url_a).kind, FAILED);

    Holding::set(&holding.hold, true);
    let before = holding.upgrades();
    assert!(unsafe { wi_relay_disconnect(relay_b, key.as_ptr()) });
    assert!(
        eventually(Duration::from_secs(3), || holding.upgrades() > before),
        "B's redial sent its upgrade"
    );
    let (operation, _dial) = dial_naming(endpoint, &public_key(53), &url_a, &[]);
    assert!(
        eventually(Duration::from_secs(5), || connected_home(endpoint)
            == Some(reported(&url_b))),
        "{:?}",
        relays(endpoint)
    );
    std::thread::sleep(Duration::from_millis(300));
    let upgrades = holding.upgrades() - before;
    assert_eq!(upgrades, 1, "B's upgrade in flight was restarted");
    unsafe { wi_cancel(operation) };
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// A dial naming more than 16 addresses fails with the cap's error before it touches a relay:
/// failed A, in a redial backoff of 2.56 s or more, isn't retried; a dial with 16 is, at once.
#[test]
fn a_dial_naming_seventeen_addresses_fails_before_it_retries_the_relay_and_one_naming_sixteen_retries_it()
 {
    let (relay_a, url_a, seen_a) = door_relay(|_, _| false);
    let (relay_b, direct_b) = spawn_relay();
    let url_b = slow_proxy(&direct_b);
    let endpoint = bind_to(54, &[(&url_a, None), (&url_b, None)]);
    let key = key_of(endpoint);
    assert!(
        eventually(Duration::from_secs(10), || seen_a.tokens(&key).len() >= 9),
        "{} refusals",
        seen_a.tokens(&key).len()
    );
    assert_eq!(state_of(endpoint, &url_a).kind, FAILED);
    let refusals = seen_a.tokens(&key).len();
    let addresses = |count: u8| -> Vec<CString> {
        (1..=count)
            .map(|n| CString::new(format!("192.0.2.{n}:4433")).unwrap())
            .collect()
    };
    let started = Instant::now();
    let (_, seventeen) = dial_naming(endpoint, &public_key(55), &url_a, &addresses(17));
    let failed = seventeen
        .recv_timeout(Duration::from_secs(1))
        .expect("an answer");
    assert_ne!(failed.status, 0);
    assert!(failed.message.contains("at most 16"), "{}", failed.message);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(seen_a.tokens(&key).len(), refusals, "A was retried");

    let (operation, _sixteen) = dial_naming(endpoint, &public_key(55), &url_a, &addresses(16));
    assert!(
        eventually(Duration::from_millis(800), || seen_a.tokens(&key).len()
            > refusals),
        "A wasn't retried"
    );
    assert!(started.elapsed() < Duration::from_millis(2500));
    unsafe { wi_cancel(operation) };
    close(endpoint);
    unsafe {
        wi_relay_free(relay_a);
        wi_relay_free(relay_b);
    }
}

/// `HOME_CONNECTING` names the latest dial or upgrade failure since the home was last
/// connected: none while it redials after a connection that was established and then lost,
/// again after a refusal came and a later connection ended it.
#[test]
fn a_home_redialling_after_an_established_connection_was_lost_names_no_error() {
    let (relay, url, holding) = holding_relay();
    let endpoint = bind(56, &url);
    let key = key_of(endpoint);
    let set = Holding::set;
    for round in 0..2 {
        assert!(eventually(Duration::from_secs(5), || connected_home(
            endpoint
        )
        .is_some()));
        // Established at its first pong, which answers the ping sent on connecting: a
        // connection lost before it is a failed attempt, named as such.
        std::thread::sleep(Duration::from_millis(300));
        set(&holding.hold, true);
        assert!(unsafe { wi_relay_disconnect(relay, key.as_ptr()) });
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut connecting = Vec::new();
        while Instant::now() < deadline {
            let state = &relays(endpoint)[0];
            if state.kind == HOME_CONNECTING {
                connecting.push(state.last_error());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        set(&holding.hold, false);
        eprintln!("round {round}: {} samples connecting", connecting.len());
        assert!(
            !connecting.is_empty(),
            "round {round}: never seen redialling"
        );
        assert!(
            connecting.iter().all(String::is_empty),
            "round {round}: {:?}",
            connecting.iter().find(|error| !error.is_empty())
        );
        assert!(eventually(Duration::from_secs(5), || connected_home(
            endpoint
        )
        .is_some()));
        if round == 0 {
            // A refusal is named while it is the latest failure; the next connection ends it.
            set(&holding.refuse, true);
            assert!(unsafe { wi_relay_disconnect(relay, key.as_ptr()) });
            assert!(
                eventually(Duration::from_secs(3), || {
                    let state = &relays(endpoint)[0];
                    state.kind != HOME_CONNECTED && !state.last_error().is_empty()
                }),
                "{:?}",
                relays(endpoint)
            );
            set(&holding.refuse, false);
        }
    }
    close(endpoint);
    unsafe { wi_relay_free(relay) };
}
