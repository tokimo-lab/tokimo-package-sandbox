#!/usr/bin/env bash
# Build Tokimo VM artifacts on macOS using Docker, then install to .vm/base/.
# Reuses CI's packaging/vm-base/build.sh for the full rootfs pipeline.
#
# Steps:
#   1) docker run rust:1.95-slim-bookworm  → builds guest binaries (musl static)
#   2) packaging/vm-base/build.sh          → builds vmlinuz + initrd + rootfs
#   3) Copy artifacts to .vm/base/
#
# Output: <repo>/.vm/base/{vmlinuz, initrd.img, rootfs/}
#
# Usage: build-vm-local.sh [--arch amd64|arm64] [--force] [--skip-init-build]
#   --arch            Target architecture (default: arm64)
#   --force           Remove existing .vm/base/ artifacts before building
#   --skip-init-build Skip guest binary build (reuse existing)

set -euo pipefail

ARCH="arm64"
FORCE=0
SKIP_INIT_BUILD=0

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)            ARCH="$2";           shift 2 ;;
        --force)           FORCE=1;             shift ;;
        --skip-init-build) SKIP_INIT_BUILD=1;   shift ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "build-vm-local: unknown arg: $1" >&2; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VM_DIR="$REPO_ROOT/.vm/base"
PKG_DIR="$REPO_ROOT/packaging/vm-local"
VM_BASE_DIR="$REPO_ROOT/packaging/vm-base"

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH" >&2; exit 1; }

if [ "$FORCE" -eq 1 ] && [ -e "$VM_DIR/vmlinuz" ]; then
    rm -rf "$VM_DIR"
fi
mkdir -p "$VM_DIR"

# ---------------------------------------------------------------------------
# 1) Guest binaries (musl static, in Docker)
# ---------------------------------------------------------------------------
if [ "$SKIP_INIT_BUILD" -eq 0 ]; then
    echo "==> [1/2] Building guest binaries ($ARCH, musl static, in rust:1.95-slim-bookworm)"
    docker run --rm --platform "linux/$ARCH" \
        -v "$REPO_ROOT:/src" \
        -e CARGO_TARGET_DIR=/tmp/target \
        -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
        -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
        -w /src \
        rust:1.95-slim-bookworm bash /src/packaging/vm-local/build-init-bin.sh "$ARCH"
else
    for bin in tokimo-sandbox-init tokimo-tun-pump tokimo-sandbox-fuse; do
        [ -f "$PKG_DIR/$bin" ] || { echo "build-vm-local: $bin not found in $PKG_DIR (drop --skip-init-build)" >&2; exit 1; }
    done
fi

# ---------------------------------------------------------------------------
# 2) Full VM build (vmlinuz + initrd + rootfs) using CI script
# ---------------------------------------------------------------------------
echo "==> [2/2] Building VM artifacts (packaging/vm-base/build.sh $ARCH)"
TOKIMO_INIT_BIN="$PKG_DIR/tokimo-sandbox-init" \
TOKIMO_TUN_PUMP_BIN="$PKG_DIR/tokimo-tun-pump" \
TOKIMO_FUSE_BIN="$PKG_DIR/tokimo-sandbox-fuse" \
bash "$VM_BASE_DIR/build.sh" "$ARCH"

# ---------------------------------------------------------------------------
# 3) Copy to .vm/base/
# ---------------------------------------------------------------------------
OUTPUT_DIR="$VM_BASE_DIR/tokimo-os-$ARCH"
echo "==> Copying to $VM_DIR"
rm -rf "$VM_DIR/rootfs"
cp "$OUTPUT_DIR/vmlinuz" "$VM_DIR/"
cp "$OUTPUT_DIR/initrd.img" "$VM_DIR/"
cp -a "$OUTPUT_DIR/rootfs" "$VM_DIR/"

echo ""
echo "==> All artifacts ready:"
ls -lh "$VM_DIR"
