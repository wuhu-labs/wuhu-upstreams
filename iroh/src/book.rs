//! The endpoint's relays as configured, which of them are benched, and the task that moves the
//! home relay off one that fails.
//!
//! iroh moves its home relay only after a net report. A relay map change runs one at once, so a
//! failure of the home relay re-inserts its entry (a retry, paced by `Pacing`). A relay that
//! keeps failing as home while its probes answer would win every report, so after `BENCH_AFTER`
//! of failure, with another relay of the map reachable in the last report, it is benched: taken
//! out of iroh's map, which runs a report without it, for a penalty of `FIRST_PENALTY` doubling
//! to `LAST_PENALTY` while it keeps failing. Every write of iroh's map goes through `writer`, and
//! every write puts the entry as configured now, so no write can undo a token change.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures_util::StreamExt;
use iroh::{Endpoint, RelayConfig, RelayMap, RelayUrl, Watcher};
use tokio::time::{Instant, sleep_until};

use crate::pacing::Pacing;

/// How long the home relay fails before it is benched, the first time since it last connected.
pub(crate) const BENCH_AFTER: Duration = Duration::from_secs(3);
/// The first bench of a relay since it last connected as home lasts this long.
pub(crate) const FIRST_PENALTY: Duration = Duration::from_secs(5);
/// Each further bench lasts twice as long as the one before, up to this.
pub(crate) const LAST_PENALTY: Duration = Duration::from_secs(300);

#[derive(Default)]
struct Book {
    /// Every relay the endpoint was configured with, as configured now (token and all).
    configured: BTreeMap<RelayUrl, Arc<RelayConfig>>,
    /// Benched relays, out of iroh's map, and when each bench ends.
    benched: HashMap<RelayUrl, Instant>,
    /// The length of each relay's last bench, kept until it connects as home again.
    penalties: HashMap<RelayUrl, Duration>,
    /// Each relay's last connection error as home: iroh drops it once a redial starts, while a
    /// redial is still the relay that failed.
    errors: HashMap<RelayUrl, String>,
}

/// One relay of the map as `wi_endpoint_relays` reads it.
pub(crate) struct Entry {
    pub(crate) url: RelayUrl,
    pub(crate) benched: bool,
    pub(crate) last_error: Option<String>,
}

pub(crate) enum TokenError {
    NotInMap,
    Closed,
}

/// Why a bench check left the home relay where it is.
enum Bench {
    Benched,
    NowhereElse,
    Closed,
}

pub(crate) struct Relays {
    endpoint: Endpoint,
    /// iroh's relay map, shared with the endpoint.
    map: RelayMap,
    book: Mutex<Book>,
    /// Held by every write of `map`, across the write's await.
    writer: tokio::sync::Mutex<()>,
    /// Taken by a retry between reading its entry and writing it: a seam for the tests.
    gate: Arc<tokio::sync::Mutex<()>>,
    failovers: AtomicU64,
}

impl Relays {
    pub(crate) fn new(endpoint: Endpoint, map: RelayMap) -> Arc<Self> {
        let configured = map
            .relays::<Vec<_>>()
            .into_iter()
            .map(|c| (c.url.clone(), c))
            .collect();
        Arc::new(Relays {
            endpoint,
            map,
            book: Mutex::new(Book {
                configured,
                ..Book::default()
            }),
            writer: tokio::sync::Mutex::new(()),
            gate: Default::default(),
            failovers: AtomicU64::new(0),
        })
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn entries(&self) -> Vec<Entry> {
        let book = self.book();
        book.configured
            .keys()
            .map(|url| Entry {
                url: url.clone(),
                benched: book.benched.contains_key(url),
                last_error: book.errors.get(url).cloned(),
            })
            .collect()
    }

    pub(crate) fn last_error(&self, url: &RelayUrl) -> Option<String> {
        self.book().errors.get(url).cloned()
    }

    pub(crate) fn failovers(&self) -> u64 {
        self.failovers.load(Ordering::Relaxed)
    }

    pub(crate) fn gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.gate.clone()
    }

    /// Replaces the token of `url`; the next dial of it presents the new one. A benched relay
    /// keeps it for when its bench ends.
    pub(crate) async fn set_auth_token(
        &self,
        url: &RelayUrl,
        config: Arc<RelayConfig>,
    ) -> Result<(), TokenError> {
        let _writer = self.writer.lock().await;
        if self.endpoint.is_closed() {
            return Err(TokenError::Closed);
        }
        let benched = {
            let mut book = self.book();
            let Some(entry) = book.configured.get_mut(url) else {
                return Err(TokenError::NotInMap);
            };
            *entry = config.clone();
            book.benched.contains_key(url)
        };
        if !benched {
            // The relay actor reads the map at every dial; a report would only cost time.
            self.map.insert(url.clone(), config);
        }
        Ok(())
    }

    /// A dial names `url`: a bench of it ends, so the dial presents its token. Its penalty stays,
    /// so a failure as home benches it again at once. iroh keeps the relay's connection actor,
    /// which may be waiting out its redial backoff (up to 16 s) from its failures as home: a
    /// network change sends every relay a check, which ends that backoff, so the dial's packets
    /// go out over a fresh connection now.
    pub(crate) async fn dialling(&self, url: &RelayUrl) {
        {
            let _writer = self.writer.lock().await;
            let config = {
                let mut book = self.book();
                if book.benched.remove(url).is_none() {
                    return;
                }
                book.configured.get(url).cloned()
            };
            let Some(config) = config else {
                return;
            };
            self.map.insert(url.clone(), config);
        }
        self.endpoint.network_change().await;
    }

    /// Re-inserts the entry of a failing home relay, as configured now, which runs a report.
    /// Returns `false` when the endpoint is closed.
    async fn retry(&self, url: &RelayUrl) -> bool {
        let _writer = self.writer.lock().await;
        let config = {
            let book = self.book();
            if book.benched.contains_key(url) {
                return true;
            }
            book.configured.get(url).cloned()
        };
        let _gate = self.gate.lock().await;
        let Some(config) = config else {
            return true;
        };
        self.endpoint
            .insert_relay(url.clone(), config)
            .await
            .is_some()
            || !self.endpoint.is_closed()
    }

    /// Benches the home relay `url` if another relay of the map answered the last report.
    async fn bench(&self, url: &RelayUrl, now: Instant) -> Bench {
        let _writer = self.writer.lock().await;
        let reachable: Vec<RelayUrl> = match self.endpoint.net_report().get() {
            Some(report) => report
                .relay_latency
                .iter()
                .map(|(_, url, _)| url.clone())
                .collect(),
            None => Vec::new(),
        };
        {
            let mut book = self.book();
            if book.benched.contains_key(url) {
                return Bench::Benched;
            }
            let elsewhere = reachable.iter().any(|other| {
                other != url
                    && book.configured.contains_key(other)
                    && !book.benched.contains_key(other)
            });
            if !elsewhere {
                return Bench::NowhereElse;
            }
            let penalty = book
                .penalties
                .get(url)
                .map_or(FIRST_PENALTY, |last| (*last * 2).min(LAST_PENALTY));
            book.penalties.insert(url.clone(), penalty);
            book.benched.insert(url.clone(), now + penalty);
            tracing::debug!(%url, ?penalty, "benching the failing home relay");
        }
        if self.endpoint.remove_relay(url).await.is_none() && self.endpoint.is_closed() {
            return Bench::Closed;
        }
        Bench::Benched
    }

    /// Ends the benches of `urls` (all of them when `None`) that are due by `now`. With
    /// `report`, the last write runs a report; otherwise the relays are back in the map for the
    /// next report and every dial. Returns `false` when the endpoint is closed.
    async fn end_benches(&self, now: Option<Instant>, report: bool) -> bool {
        let _writer = self.writer.lock().await;
        let ending: Vec<(RelayUrl, Arc<RelayConfig>)> = {
            let mut book = self.book();
            let due: Vec<RelayUrl> = book
                .benched
                .iter()
                .filter(|(_, until)| now.is_none_or(|now| **until <= now))
                .map(|(url, _)| url.clone())
                .collect();
            due.into_iter()
                .filter_map(|url| {
                    book.benched.remove(&url);
                    book.configured
                        .get(&url)
                        .map(|config| (url, config.clone()))
                })
                .collect()
        };
        let count = ending.len();
        for (n, (url, config)) in ending.into_iter().enumerate() {
            tracing::debug!(%url, "a bench ends");
            if report && n + 1 == count {
                if self.endpoint.insert_relay(url, config).await.is_none()
                    && self.endpoint.is_closed()
                {
                    return false;
                }
            } else {
                self.map.insert(url, config);
            }
        }
        true
    }

    fn next_bench_end(&self) -> Option<Instant> {
        self.book().benched.values().min().copied()
    }

    fn any_benched(&self) -> bool {
        !self.book().benched.is_empty()
    }

    /// Whether `url` was benched since it last connected as home.
    fn was_benched(&self, url: &RelayUrl) -> bool {
        self.book().penalties.contains_key(url)
    }

    fn connected(&self, url: &RelayUrl) {
        let mut book = self.book();
        book.errors.remove(url);
        book.penalties.remove(url);
    }

    fn failed(&self, url: &RelayUrl, error: String) {
        self.book().errors.insert(url.clone(), error);
    }

    /// The failover task: retries a failing home relay, benches one that keeps failing, ends
    /// benches. Ends with the endpoint.
    pub(crate) async fn run(self: Arc<Self>) {
        let closing = self.endpoint.clone();
        let closed = async move { closing.closed().await };
        let mut statuses = self
            .endpoint
            .home_relay_status()
            .stream_updates_only()
            .take_until(closed)
            .boxed();
        let closing = self.endpoint.clone();
        let mut reports = self
            .endpoint
            .net_report()
            .stream_updates_only()
            .take_until(async move { closing.closed().await })
            .boxed();
        let mut pacing = Pacing::new(Instant::now());
        // The failing home relay to retry once `pacing` allows.
        let mut retry: Option<RelayUrl> = None;
        // The home relay that failed since it last connected, and when it first did.
        let mut failing: Option<(RelayUrl, Instant)> = None;
        // When to check whether to bench `failing`; re-armed by each report.
        let mut bench_check: Option<Instant> = None;
        let mut home_connected = false;
        loop {
            let bench_end = self.next_bench_end();
            tokio::select! {
                next = statuses.next() => {
                    let Some(statuses) = next else {
                        return;
                    };
                    let Some(home) = statuses.first() else {
                        continue;
                    };
                    let now = Instant::now();
                    home_connected = home.is_connected();
                    if home.is_connected() {
                        self.connected(home.url());
                        pacing.connected(now);
                        (retry, failing, bench_check) = (None, None, None);
                    } else if let Some(error) = home.last_error() {
                        self.failed(home.url(), format!("{error:#}"));
                        if failing.as_ref().is_none_or(|(url, _)| url != home.url()) {
                            let delay = if self.was_benched(home.url()) {
                                Duration::ZERO
                            } else {
                                BENCH_AFTER
                            };
                            failing = Some((home.url().clone(), now));
                            bench_check = Some(now + delay);
                        }
                        retry = Some(home.url().clone());
                    } else if failing.as_ref().is_some_and(|(url, _)| url != home.url()) {
                        // A new home, still connecting.
                        (failing, bench_check) = (None, None);
                    }
                }
                next = reports.next() => {
                    if next.is_none() {
                        return;
                    }
                    if let Some((url, since)) = &failing && bench_check.is_none() {
                        let delay = if self.was_benched(url) { Duration::ZERO } else { BENCH_AFTER };
                        bench_check = Some((*since + delay).max(Instant::now()));
                    }
                }
                () = sleep_until(pacing.ready_at), if retry.is_some() => {}
                () = sleep_until(bench_check.unwrap_or_else(Instant::now)), if bench_check.is_some() => {}
                () = sleep_until(bench_end.unwrap_or_else(Instant::now)), if bench_end.is_some() => {}
            }
            let now = Instant::now();
            if bench_end.is_some_and(|end| end <= now)
                && !self.end_benches(Some(now), !home_connected).await
            {
                return;
            }
            if let Some((url, _)) = &failing
                && bench_check.is_some_and(|at| at <= now)
            {
                bench_check = None;
                match self.bench(url, now).await {
                    Bench::Benched => retry = None,
                    Bench::NowhereElse if self.any_benched() && now >= pacing.ready_at => {
                        // Every other relay is benched: they come back rather than leave the
                        // endpoint on a home relay that fails.
                        pacing.fired(now);
                        if !self.end_benches(None, true).await {
                            return;
                        }
                    }
                    Bench::NowhereElse => {}
                    Bench::Closed => return,
                }
            }
            if now >= pacing.ready_at
                && let Some(url) = retry.take()
            {
                pacing.fired(now);
                self.failovers.fetch_add(1, Ordering::Relaxed);
                if !self.retry(&url).await {
                    return;
                }
            }
        }
    }
}
