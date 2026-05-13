#!/usr/bin/env bash
# Build guest binaries (musl static). Run inside rust:1.95-slim-bookworm.
#
# Usage: build-init-bin.sh [--arch amd64|arm64]
#   --arch   Target architecture (default: amd64)
set -euo pipefail

ARCH="${1:-amd64}"
case "$ARCH" in
    amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;;
    arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "build-init-bin: unsupported arch $ARCH (amd64|arm64)" >&2; exit 1 ;;
esac

# Use a separate target dir to avoid conflicts with host-side build artifacts.
export CARGO_TARGET_DIR=/tmp/target

apt-get update -qq
apt-get install -y -qq musl-tools >/dev/null
rustup target add "$RUST_TARGET" >/dev/null

# Force fully-static linkage. Rust 1.71+ defaults *-linux-musl targets to
# *dynamic* musl, embedding an ELF INTERP pointing at /lib/ld-musl-x86_64.so.1.
# Neither our initrd nor the guest rootfs ships that interpreter, so the
# binaries fail with ENOENT ("chroot: can't execute ...: No such file or
# directory") even though the file is right there.
#
# We:
#   - drop any musl-gcc linker override so rustc's bundled rust-lld is used
#     (musl-gcc emits a dynamic exe even with +crt-static)
#   - use rust's self-contained musl libs (link-self-contained=yes)
#   - require +crt-static so PT_INTERP is omitted
unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER
unset CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER
export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static -C link-self-contained=yes"

echo "==> Building guest binaries for $ARCH ($RUST_TARGET)"
cargo build --release --target "$RUST_TARGET" \
    --bin tokimo-sandbox-init \
    --bin tokimo-tun-pump \
    --bin tokimo-sandbox-fuse

OUT_DIR="packaging/vm-local"
mkdir -p "$OUT_DIR"
for bin in tokimo-sandbox-init tokimo-tun-pump tokimo-sandbox-fuse; do
    cp "$CARGO_TARGET_DIR/$RUST_TARGET/release/$bin" "$OUT_DIR/$bin"
    chmod +x "$OUT_DIR/$bin"
done
ls -lh "$OUT_DIR"/tokimo-sandbox-init "$OUT_DIR"/tokimo-tun-pump "$OUT_DIR"/tokimo-sandbox-fuse
