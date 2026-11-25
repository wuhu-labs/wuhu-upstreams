# tailcat for Wuhu

Static archives of Wuhu's Tailcat bridge, built by `tailcat/build.sh` in github.com/wuhu-labs/wuhu-upstreams against [wuhu-labs/tailcat](https://github.com/wuhu-labs/tailcat) at the revision in `tailcat/pin.env`.

- Upstream base: e99a945255293ae97402680526172e0b4bbd7d1b (v0.7.0 plus 45 commits).
- Fork commit: a68ed208b6b6f0017b9f14bbc1848248164a2ecc. It adds `Server.Dial` on the configured DERP region, adds the listener's path-discovery key to the meow reply, and refreshes the handshake before retrying a timed-out stream to a known peer. `Client` is unchanged.
- Source: `https://github.com/wuhu-labs/tailcat/archive/<commit>.tar.gz`, SHA-256 618dadee35be4ec856a7eeaa9fdbdbfeb8597e7da3673bf6297929233cfe8c1c, republished byte-for-byte as the release's `-source.tar.gz`.
- License: BSD-3-Clause (`LICENSE`, shipped in every artifact).
- The first-party bridge (`tailcat/wuhu`) is added to the unpacked source as `cmd/wuhutailcat`. It uses public Tailcat and Tailscale APIs. Tailscale is unmodified, and the build tags are Tailcat's `build-tags.txt`.
- Go: the toolchain `go.mod` names (1.27.4), `CGO_ENABLED=1`, `-trimpath`.

## The bridge

`wuhu_tailcat.h` is the whole ABI. The original forwarding node (`wt_node`, `wt_node_forward`, `wt_node_check`) and CONNECT proxy (`wt_proxy`, `wt_proxy_route`) are unchanged. Its node loads and locks an identity file and forwards client streams to a local TCP endpoint.

V2 (`wt_node_v2`) listens and dials on one engine per process. It derives the X25519 node key from a caller-supplied Ed25519 seed and has no files or WireGuard pre-shared key. The caller uses `wt_peer_key` to convert enrolled Ed25519 public keys to the X25519 peer IDs used for admission, dialing, and reporting accepted peers. Dial and accept hand over a Unix stream FD; Tailcat's `ProxyConns` preserves half-close in both directions.

A `wt_relay` serves DERP on a plaintext stream FD handed over after the HTTP upgrade. The stock DERP server authenticates the key before calling the fail-closed admission hook through a private loopback verifier. An internal mesh client on an in-memory connection reports key presence; no mesh credential is exposed through the ABI. The relay and node can run in the same process. `wt_close` shuts down each handle's owned resources; callers close the stream FDs they received.

## Artifacts

- `tailcat-<version>-apple.zip`: `CTailcat.xcframework` with arm64 slices `macos-arm64` (macOS 14.0 floor), `ios-arm64` and `ios-arm64-simulator` (iOS 17.0 floor, upstream's clang wrappers). Consumers link `-framework CoreFoundation -framework Security -lresolv`.
- `tailcat-<version>-linux-x86_64.tar.gz` and `tailcat-<version>-linux-arm64.tar.gz`: `include/{wuhu_tailcat.h,module.modulemap}` and `lib/libtailcat.a`, built natively with `-buildmode=c-archive` and `-ldflags "-s -w"` on Ubuntu 22.04 (glibc 2.35 floor), only packaged after the Go tests and linked C ABI smoke test pass. The archives need nothing beyond libc.
- `tailcat-<version>-source.tar.gz`: the exact fork source above.

Release `tailcat/0.7.0-45-ge99a945` holds the earlier archives of upstream's own `cmd/libtailcat`; it stays as published.
