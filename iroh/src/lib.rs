//! Wuhu's C ABI over iroh: the whole contract is `include/wuhu_iroh.h`.

mod endpoint;
mod op;
mod relay;
mod stream;
mod watch;

/// For the crate's own tests, never part of the C ABI: how many net reports `endpoint` (a
/// `wi_endpoint`) has run.
#[doc(hidden)]
pub use endpoint::net_reports;

/// For the crate's own tests: runs one full net report, as the periodic one does.
#[doc(hidden)]
pub use endpoint::run_net_report;
