#!/bin/sh
# Builds Wuhu's C ABI over iroh (iroh/include/wuhu_iroh.h) as static archives, with the crate
# versions Cargo.lock pins and the toolchain rust-toolchain.toml pins.
#
#   iroh/build.sh apple <out>   CIroh.xcframework, arm64 macOS/iOS/iOS simulator (macOS, Xcode)
#   iroh/build.sh linux <out>   native x86_64 Linux archive (glibc), after the ABI tests
set -eu

here=$(cd "$(dirname "$0")" && pwd)
kind=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
version=$(sed -n 's/^iroh = .*"=\([0-9.]*\)".*/\1/p' "$here/Cargo.toml")
test -n "$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$here"
target_dir=${CARGO_TARGET_DIR:-$here/target}

stage="$work/stage"
mkdir -p "$stage/include"
cp "$here/include/wuhu_iroh.h" "$here/include/module.modulemap" "$stage/include/"
cp "$here/PROVENANCE.md" "$here/Cargo.lock" "$stage/"

# archive <rust target>: builds the archive of one slice and copies it to $work/lib/<target>, the
# only archive packaged; prints the native libraries it needs. The target directory may be reused
# (CI caches it), so the archive an earlier build left there is removed first, and a failed build
# fails the script.
archive() {
  built="$target_dir/$1/release/libwuhu_iroh.a"
  rm -f "$built"
  if ! RUSTFLAGS="--print=native-static-libs" cargo build --locked --release --target "$1" --lib \
    >"$work/build-$1.log" 2>&1; then
    cat "$work/build-$1.log" >&2
    echo "cargo build --target $1 failed" >&2
    exit 1
  fi
  grep -E 'native-static-libs|warning' "$work/build-$1.log" || true
  test -f "$built" || { echo "cargo build --target $1 wrote no $built" >&2; exit 1; }
  mkdir -p "$work/lib/$1"
  cp "$built" "$work/lib/$1/"
}

case "$kind" in
apple)
  export MACOSX_DEPLOYMENT_TARGET=14.0 IPHONEOS_DEPLOYMENT_TARGET=17.0
  for t in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim; do
    rustup target add "$t"
    archive "$t"
  done
  xcodebuild -create-xcframework \
    -library "$work/lib/aarch64-apple-darwin/libwuhu_iroh.a" -headers "$stage/include" \
    -library "$work/lib/aarch64-apple-ios/libwuhu_iroh.a" -headers "$stage/include" \
    -library "$work/lib/aarch64-apple-ios-sim/libwuhu_iroh.a" -headers "$stage/include" \
    -output "$work/apple/CIroh.xcframework"
  cp "$here/PROVENANCE.md" "$here/Cargo.lock" "$work/apple/"
  (cd "$work/apple" && zip -qry "$out/iroh-$version-apple.zip" .)
  ;;
linux)
  [ "$(uname -m)" = x86_64 ] || { echo "linux builds x86_64 only" >&2; exit 2; }
  cargo test --locked --release
  archive x86_64-unknown-linux-gnu
  mkdir -p "$stage/lib"
  cp "$work/lib/x86_64-unknown-linux-gnu/libwuhu_iroh.a" "$stage/lib/"
  tar -czf "$out/iroh-$version-linux-x86_64.tar.gz" -C "$stage" .
  ;;
*)
  echo "usage: $0 apple|linux <out>" >&2
  exit 2
  ;;
esac
