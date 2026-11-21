#!/bin/sh
# Builds libtailcat (the upstream C ABI, cmd/libtailcat) as static archives
# from the pinned upstream revision, with upstream's release build tags.
#
#   tailcat/build.sh apple <out>   CTailcat.xcframework via upstream's swift/Makefile (macOS, Xcode)
#   tailcat/build.sh linux <out>   x86_64-linux-gnu c-archive (glibc)
#
# Needs the Go toolchain go.mod names (GOTOOLCHAIN=local) and a C compiler.
set -eu

. "$(dirname "$0")/pin.env"

kind=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

source_tarball="$out/tailcat-$VERSION-source.tar.gz"
curl -fsSL "https://github.com/tailscale/tailcat/archive/$COMMIT.tar.gz" -o "$source_tarball"
echo "$SOURCE_SHA256  $source_tarball" | shasum -a 256 -c -
tar -xzf "$source_tarball" -C "$work"
src="$work/tailcat-$COMMIT"

want=$(sed -n 's/^go //p' "$src/go.mod")
have=$(GOTOOLCHAIN=local go env GOVERSION)
[ "$have" = "go$want" ] || { echo "go.mod wants go$want, have $have" >&2; exit 1; }
export GOTOOLCHAIN=local CGO_ENABLED=1 GOFLAGS=-trimpath

stage="$work/stage"
mkdir -p "$stage"
cp "$src/LICENSE" "$stage/LICENSE"
cp "$(dirname "$0")/PROVENANCE.md" "$stage/PROVENANCE.md"

case "$kind" in
apple)
  make -C "$src/swift" xcframework
  cp -R "$src/swift/CTailcat.xcframework" "$stage/"
  (cd "$stage" && zip -qry "$out/tailcat-$VERSION-apple.zip" .)
  ;;
linux)
  mkdir -p "$stage/include" "$stage/lib"
  (cd "$src" && go build -buildmode=c-archive -tags "$(cat build-tags.txt)" \
    -ldflags "-s -w" -o "$work/libtailcat.a" ./cmd/libtailcat)
  cp "$work/libtailcat.a" "$stage/lib/"
  cp "$src/cmd/libtailcat/tailcat.h" "$src/swift/include/module.modulemap" "$stage/include/"
  tar -czf "$out/tailcat-$VERSION-linux-x86_64.tar.gz" -C "$stage" .
  ;;
*)
  echo "usage: $0 apple|linux <out>" >&2
  exit 2
  ;;
esac
