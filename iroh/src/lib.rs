//! Wuhu's C ABI over iroh: the whole contract is `include/wuhu_iroh.h`.

mod book;
mod endpoint;
mod op;
mod pacing;
mod relay;
mod stream;
mod watch;

/// For the crate's own tests, never part of the C ABI: how many net reports `endpoint` (a
/// `wi_endpoint`) has run.
#[doc(hidden)]
pub use endpoint::net_reports;

/// For the crate's own tests: how many failovers `endpoint` has started.
#[doc(hidden)]
pub use endpoint::failovers;

/// For the crate's own tests: a lock that a failover's retry takes between reading its relay's
/// entry and writing it back.
#[doc(hidden)]
pub use endpoint::failover_gate;
