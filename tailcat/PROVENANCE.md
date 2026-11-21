# tailcat for Wuhu

Static archives of Wuhu's tailcat bridge, built by `tailcat/build.sh` in github.com/wuhu-labs/wuhu-upstreams against [tailscale/tailcat](https://github.com/tailscale/tailcat) at the revision in `tailcat/pin.env`.

- Upstream commit: e99a945255293ae97402680526172e0b4bbd7d1b (v0.7.0 plus 45 commits).
- Source: `https://github.com/tailscale/tailcat/archive/<commit>.tar.gz`, sha256 f96906f9ae9e229787c7dafc236dc5b5318b6322503bad88060c6ba20df4f6a8, republished byte-for-byte as the release's `-source.tar.gz`.
- License: BSD-3-Clause (`LICENSE`, shipped in every artifact).
- Upstream modifications: none. The bridge (`tailcat/wuhu`: `bridge.go`, `tunnel.go`, their tests, `wuhu_tailcat.h`, `module.modulemap` for module `CTailcat`) is first-party Wuhu code, added to the unpacked source as `cmd/wuhutailcat` so it builds with upstream's `go.mod`; it uses only the public `tailcat` package. Build tags are upstream's `build-tags.txt`.
- Go: the toolchain `go.mod` names (1.27.4), `CGO_ENABLED=1`, `-trimpath`.

## The bridge

`wuhu_tailcat.h` is the whole ABI: a node (`wt_node`, `wt_node_forward`) that joins tailcat and splices each client stream to one local TCP endpoint, and a loopback HTTP CONNECT proxy (`wt_proxy`, `wt_proxy_route`) that tunnels one authority, behind one credential, to one tailcat server. Each handle owns its listeners, peers and connections; `wt_close` ends them all. Streams are spliced by upstream's `ProxyConns` (half-close, FIN drain).

## Artifacts

- `tailcat-<version>-apple.zip`: `CTailcat.xcframework` with arm64 slices `macos-arm64` (macOS 14.0 floor), `ios-arm64` and `ios-arm64-simulator` (iOS 17.0 floor, upstream's clang wrappers). Consumers link `-framework CoreFoundation -framework Security -lresolv`.
- `tailcat-<version>-linux-x86_64.tar.gz`: `include/{wuhu_tailcat.h,module.modulemap}` and `lib/libtailcat.a`, a `-buildmode=c-archive` build for linux/amd64 with `-ldflags "-s -w"` on Ubuntu 22.04 (glibc 2.35 floor), after the bridge's tests pass. It needs nothing beyond libc.
- `tailcat-<version>-source.tar.gz`: the exact upstream source above.

Release `tailcat/0.7.0-45-ge99a945` holds the earlier archives of upstream's own `cmd/libtailcat`; it stays as published.
