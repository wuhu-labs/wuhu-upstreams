#!/bin/sh
# Builds Wuhu's tailcat bridge (tailcat/wuhu, C ABI wuhu_tailcat.h) as static
# archives against the pinned upstream revision, with upstream's release build
# tags. The bridge is compiled as cmd/wuhutailcat inside the upstream module,
# which it uses only through the public tailcat package.
#
#   tailcat/build.sh apple <out>   CTailcat.xcframework, arm64 macOS/iOS/iOS simulator (macOS, Xcode)
#   tailcat/build.sh linux <out>   x86_64-linux-gnu c-archive (glibc), after the bridge's tests
#
# Needs the Go toolchain go.mod names (GOTOOLCHAIN=local) and a C compiler.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
. "$here/pin.env"

kind=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

source_tarball="$out/tailcat-$VERSION-source.tar.gz"
curl -fsSL "https://github.com/tailscale/tailcat/archive/$COMMIT.tar.gz" -o "$source_tarball"
echo "$SOURCE_SHA256  $source_tarball" | shasum -a 256 -c -
tar -xzf "$source_tarball" -C "$work"
src="$work/tailcat-$COMMIT"
mkdir "$src/cmd/wuhutailcat"
cp "$here"/wuhu/*.go "$src/cmd/wuhutailcat/"

want=$(sed -n 's/^go //p' "$src/go.mod")
have=$(GOTOOLCHAIN=local go env GOVERSION)
[ "$have" = "go$want" ] || { echo "go.mod wants go$want, have $have" >&2; exit 1; }
export GOTOOLCHAIN=local CGO_ENABLED=1 GOFLAGS=-trimpath
tags=$(cat "$src/build-tags.txt")

stage="$work/stage"
mkdir -p "$stage/include"
cp "$src/LICENSE" "$here/PROVENANCE.md" "$stage/"
cp "$here/wuhu/wuhu_tailcat.h" "$here/wuhu/module.modulemap" "$stage/include/"

# archive <slice> <goos> <goarch> <cc> <tags> <ldflags>
archive() {
  (cd "$src" && GOOS=$2 GOARCH=$3 CC=$4 go build -buildmode=c-archive -tags "$5" -ldflags "$6" \
    -o "$work/$1/libtailcat.a" ./cmd/wuhutailcat)
}

case "$kind" in
apple)
  (export MACOSX_DEPLOYMENT_TARGET=14.0 CGO_CFLAGS=-mmacos-version-min=14.0 CGO_LDFLAGS=-mmacos-version-min=14.0 &&
    archive macos darwin arm64 clang "$tags" "-s -w")
  archive ios ios arm64 "$src/swift/script/clangwrap-ios.sh" "ios,$tags" -w
  archive iossim ios arm64 "$src/swift/script/clangwrap-ios-sim-arm.sh" "ios,$tags" -w
  xcodebuild -create-xcframework \
    -library "$work/macos/libtailcat.a" -headers "$stage/include" \
    -library "$work/ios/libtailcat.a" -headers "$stage/include" \
    -library "$work/iossim/libtailcat.a" -headers "$stage/include" \
    -output "$work/apple/CTailcat.xcframework"
  cp "$src/LICENSE" "$here/PROVENANCE.md" "$work/apple/"
  (cd "$work/apple" && zip -qry "$out/tailcat-$VERSION-apple.zip" .)
  ;;
linux)
  (cd "$src" && go test -count=1 -timeout 300s ./cmd/wuhutailcat)
  archive linux linux amd64 cc "$tags" "-s -w"
  mkdir -p "$stage/lib"
  cp "$work/linux/libtailcat.a" "$stage/lib/"
  tar -czf "$out/tailcat-$VERSION-linux-x86_64.tar.gz" -C "$stage" .
  ;;
*)
  echo "usage: $0 apple|linux <out>" >&2
  exit 2
  ;;
esac
