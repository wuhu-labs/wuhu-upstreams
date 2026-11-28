//! How often a failing home relay may start a failover.

use std::time::Duration;

use tokio::time::Instant;

pub(crate) const FIRST_GAP: Duration = Duration::from_millis(500);
pub(crate) const LAST_GAP: Duration = Duration::from_secs(16);

/// A failover may run at once after the home relay was connected; while it stays down, each one
/// waits a gap that doubles from `FIRST_GAP` to `LAST_GAP`, whatever iroh's own redials do.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pacing {
    pub(crate) ready_at: Instant,
    gap: Duration,
}

impl Pacing {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            ready_at: now,
            gap: FIRST_GAP,
        }
    }

    pub(crate) fn fired(&mut self, now: Instant) {
        self.ready_at = now + self.gap;
        self.gap = (self.gap * 2).min(LAST_GAP);
    }

    pub(crate) fn connected(&mut self, now: Instant) {
        *self = Self::new(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gap_doubles_to_sixteen_seconds_and_a_connection_resets_it() {
        let start = Instant::now();
        let mut pacing = Pacing::new(start);
        assert_eq!(pacing.ready_at, start);
        let mut now = start;
        let mut gaps = Vec::new();
        for _ in 0..8 {
            pacing.fired(now);
            gaps.push(pacing.ready_at - now);
            now = pacing.ready_at;
        }
        let ms = |ms| Duration::from_millis(ms);
        assert_eq!(
            gaps,
            [500, 1000, 2000, 4000, 8000, 16000, 16000, 16000].map(ms)
        );
        pacing.connected(now);
        assert_eq!(pacing.ready_at, now);
        pacing.fired(now);
        assert_eq!(pacing.ready_at - now, FIRST_GAP);
    }
}
