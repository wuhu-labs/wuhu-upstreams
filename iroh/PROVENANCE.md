# iroh for Wuhu

Static archives of `wuhu_iroh`, Wuhu's C ABI over [iroh](https://github.com/n0-computer/iroh) and its embedded relay (`iroh-relay`, feature `server`), built by `iroh/build.sh` in github.com/wuhu-labs/wuhu-upstreams.

- Upstream: the crates.io releases `iroh` and `iroh-relay` at the exact version `Cargo.toml` names, with every transitive crate at the version and checksum `Cargo.lock` records (shipped in every artifact), except the crates `[patch.crates-io]` in `Cargo.toml` takes from a fork at an exact commit.
- Patched: two forks, on their branch `wuhu` over the upstream release:
  - [wuhu-labs/iroh](https://github.com/wuhu-labs/iroh) `54cef96d`, two commits on `v1.5.0` (`iroh`, `iroh-base`, `iroh-dns`, `iroh-relay`), both in `iroh/src/socket/transports/relay/actor.rs`. `327dc811`: a relay connection check (sent on a major network change) while the relay is not connected restarts a dial in flight and ends a reconnect backoff, instead of waiting out the 10 s connect timeout or the backoff delay (up to 16 s); tests `check_connection_restarts_a_stalled_dial`, `check_connection_ends_backoff`. `54cef96d`: every dial presents the relay's auth token as the relay map holds it at that moment, so a token replaced on a running endpoint is presented on the next connection (upstream reads it once, when the relay's actor starts, and the home relay's actor lives as long as the endpoint); a live connection is not touched; test `dial_presents_the_current_auth_token`.
  - [wuhu-labs/noq](https://github.com/wuhu-labs/noq) `08630983`, one commit on the `noq` 1.5.0 release commit `c7b87d58` (`noq`, `noq-proto`, `noq-udp`): a local reset resolves `SendStream::stopped()` with `None`, and a resolving `stopped()` removes the stream's notifier, so a stream waited on and then reset locally no longer keeps one until its connection closes. Test: `stream_stopped_after_local_reset` in `noq/src/tests.rs`.
- License: iroh is MIT OR Apache-2.0; the crate here is first-party.
- Rust: the toolchain `rust-toolchain.toml` names, release profile with LTO and `panic = "unwind"` so no panic crosses the ABI.

## The ABI

`include/wuhu_iroh.h` is the whole contract: endpoints made from an Ed25519 secret key and one relay URL (relay only, or relay plus direct UDP; no discovery service), connections whose accept hands over the verified caller key, bidirectional streams with QUIC backpressure, path and relay state, `network_change`, and an embedded relay with caller admission (`on_connect`, `on_disconnect`) and `disconnect(key)`. Asynchronous calls complete through a callback, exactly once, and can be cancelled.

## Artifacts

- `iroh-<version>-apple.zip`: `CIroh.xcframework` with arm64 slices `macos-arm64` (macOS 14.0 floor), `ios-arm64` and `ios-arm64-simulator` (iOS 17.0 floor). Consumers link `-framework CoreFoundation -framework Security -framework SystemConfiguration`.
- `iroh-<version>-linux-x86_64.tar.gz`: `include/{wuhu_iroh.h,module.modulemap}` and `lib/libwuhu_iroh.a`, built on Ubuntu 22.04 (glibc 2.35 floor), packaged only after `cargo test` (the ABI end to end on localhost) passes. Consumers link `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc`.
