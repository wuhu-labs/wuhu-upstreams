# tailcat for Wuhu

Static archives of libtailcat, the C ABI of [tailscale/tailcat](https://github.com/tailscale/tailcat) (`cmd/libtailcat`, ABI version 1), built by `tailcat/build.sh` in github.com/wuhu-labs/wuhu-upstreams from the revision in `tailcat/pin.env`.

- Upstream commit: e99a945255293ae97402680526172e0b4bbd7d1b (v0.7.0 plus 45 commits; no upstream tag carries the C ABI's Swift packaging yet).
- Source: `https://github.com/tailscale/tailcat/archive/<commit>.tar.gz`, sha256 f96906f9ae9e229787c7dafc236dc5b5318b6322503bad88060c6ba20df4f6a8, republished byte-for-byte as the release's `-source.tar.gz`.
- License: BSD-3-Clause (`LICENSE`, shipped in every artifact).
- Upstream modifications: none. Build tags are upstream's `build-tags.txt`; the header and module map are upstream's `cmd/libtailcat/tailcat.h` and `swift/include/module.modulemap` (module `CTailcat`).
- Go: the toolchain `go.mod` names (1.27.4), `CGO_ENABLED=1`, `-trimpath`.

## Artifacts

- `tailcat-<version>-apple.zip`: `CTailcat.xcframework` from upstream's `swift/Makefile` (`make xcframework`, unmodified): `macos-arm64_x86_64` (macOS 14.0 floor), `ios-arm64` and `ios-arm64_x86_64-simulator` (iOS 17.0 floor). Consumers link `-framework CoreFoundation -framework Security -lresolv`.
- `tailcat-<version>-linux-x86_64.tar.gz`: `include/{tailcat.h,module.modulemap}` and `lib/libtailcat.a`, a `-buildmode=c-archive` build for linux/amd64 with `-ldflags "-s -w"` on Ubuntu 22.04 (glibc 2.35 floor). It needs nothing beyond libc.
- `tailcat-<version>-source.tar.gz`: the exact upstream source above.
