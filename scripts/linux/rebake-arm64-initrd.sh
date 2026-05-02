#!/usr/bin/env bash
# rebake-arm64-initrd.sh — local rebake of the arm64 macOS VM initrd.
#
# Runs scripts/rebake-arm64-initrd-inside-docker.sh inside an
# rust:1.95-slim-bookworm linux/arm64 container so we can:
#   1) cross-build tokimo-sandbox-init + tokimo-tun-pump (aarch64-musl),
#   2) fetch tun.ko matching the guest kernel from Debian archives,
#   3) repack initrd via packaging/vm/scripts/rebake-initrd.sh.
#
# Output: packaging/vm-base/tokimo-os-arm64/initrd.img (overwritten).
#
# Idempotent: cargo target dir is mounted into the container so the
# build is incremental across runs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARM64_DIR="$REPO_ROOT/packaging/vm-base/tokimo-os-arm64"
VMLINUZ="$ARM64_DIR/vmlinuz"

[ -f "$VMLINUZ" ] || { echo "missing vmlinuz: $VMLINUZ" >&2; exit 1; }
# `strings | grep -m1` triggers SIGPIPE on `strings` after grep exits;
# under `set -o pipefail` that propagates as a script failure. Disable
# pipefail just for this one extraction.
set +o pipefail
KVER=$(strings "$VMLINUZ" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\+deb[0-9]+-(arm64|amd64)' | head -n1)
set -o pipefail
[ -n "$KVER" ] || { echo "could not detect kernel version from $VMLINUZ" >&2; exit 1; }
echo "==> guest kernel: $KVER"

command -v docker >/dev/null 2>&1 || { echo "docker not on PATH" >&2; exit 1; }

docker run --rm --platform linux/arm64 \
    -v "$REPO_ROOT:/src" \
    -w /src \
    -e KVER="$KVER" \
    -e CARGO_TARGET_DIR=/src/target/docker-arm64 \
    -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    rust:1.95-slim-bookworm \
    bash /src/scripts/linux/rebake-arm64-initrd-inside-docker.sh

echo
echo "==> done. New initrd at $ARM64_DIR/initrd.img"
ls -la "$ARM64_DIR/initrd.img"
