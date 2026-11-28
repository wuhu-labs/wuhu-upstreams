//! Wuhu's C ABI over iroh: the whole contract is `include/wuhu_iroh.h`.

mod endpoint;
mod op;
mod relay;
mod stream;
mod watch;

/// For the crate's own tests (the `test-hooks` feature, which the release build leaves out),
/// never part of the C ABI: how many net reports `endpoint` (a `wi_endpoint`) has started.
#[cfg(feature = "test-hooks")]
pub use endpoint::net_reports;

/// For the crate's own tests (the `test-hooks` feature): runs a full net report, as a relay map
/// change does, and returns once a full report that started after the call has completed.
/// Reads and writes no relay entry.
#[cfg(feature = "test-hooks")]
pub use endpoint::run_net_report;
