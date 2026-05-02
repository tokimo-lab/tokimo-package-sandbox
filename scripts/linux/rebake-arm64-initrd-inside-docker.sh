#!/usr/bin/env bash
# Run inside rust:1.95-slim-bookworm linux/arm64 — invoked by
# scripts/linux/rebake-arm64-initrd.sh. Builds aarch64-musl init + tun-pump,
# fetches tun.ko for the guest kernel, and rebakes the initrd in-place.
#
# Reads $KVER (e.g. "6.12.85+deb13-arm64") from environment.

set -euo pipefail

[ -n "${KVER:-}" ] || { echo "KVER env not set" >&2; exit 1; }

# --- 1. Toolchain ------------------------------------------------------
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    musl-tools musl-dev cpio gzip xz-utils ca-certificates curl dpkg
rustup target add aarch64-unknown-linux-musl

# --- 2. Build init + tun-pump + fuse ---------------------------------
echo "==> cross-build aarch64-unknown-linux-musl"
cd /src
cargo build --release --target aarch64-unknown-linux-musl \
    --bin tokimo-sandbox-init --bin tokimo-tun-pump --bin tokimo-sandbox-fuse

INIT_BIN=${CARGO_TARGET_DIR:-/src/target}/aarch64-unknown-linux-musl/release/tokimo-sandbox-init
PUMP_BIN=${CARGO_TARGET_DIR:-/src/target}/aarch64-unknown-linux-musl/release/tokimo-tun-pump
FUSE_BIN=${CARGO_TARGET_DIR:-/src/target}/aarch64-unknown-linux-musl/release/tokimo-sandbox-fuse
[ -x "$INIT_BIN" ] || { echo "init bin missing" >&2; exit 1; }
[ -x "$PUMP_BIN" ] || { echo "pump bin missing" >&2; exit 1; }
[ -x "$FUSE_BIN" ] || { echo "fuse bin missing" >&2; exit 1; }
ls -la "$INIT_BIN" "$PUMP_BIN" "$FUSE_BIN"

# --- 3. Fetch tun.ko for the guest kernel -----------------------------
EXTRAS=/tmp/extras
mkdir -p "$EXTRAS"

echo "deb http://deb.debian.org/debian trixie main" \
    > /etc/apt/sources.list.d/debian-trixie.list
echo "deb http://security.debian.org/debian-security trixie-security main" \
    >> /etc/apt/sources.list.d/debian-trixie.list
apt-get update -qq

cd /tmp
if ! apt-get download "linux-image-${KVER}-unsigned" 2>/dev/null; then
    apt-get download "linux-image-${KVER}"
fi
DEB_FILE=$(ls /tmp/linux-image-${KVER}*.deb | head -1)
echo "==> downloaded $DEB_FILE"

EXTRACT=/tmp/kpkg
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"
dpkg-deb -x "$DEB_FILE" "$EXTRACT"

# Modules may live under /lib/modules or /usr/lib/modules (usrmerge).
TUN_PATH=$(find "$EXTRACT" -path '*/modules/*' -name 'tun.ko*' | head -1)
[ -n "$TUN_PATH" ] || { echo "tun.ko not found in $DEB_FILE; deb contents:" >&2; find "$EXTRACT" -name '*.ko*' | head -10 >&2; exit 1; }
echo "==> tun module: $TUN_PATH"
cp "$TUN_PATH" "$EXTRAS/"

# NFS client modules (LEGACY — kept for one release).
for mod in sunrpc auth_rpcgss lockd grace nfs_acl nfs nfsv3; do
    P=$(find "$EXTRACT" -path '*/modules/*' -name "${mod}.ko*" | head -1 || true)
    if [ -n "$P" ]; then
        echo "==> nfs module: $P"
        cp "$P" "$EXTRAS/"
    else
        echo "==> nfs module: ${mod}.ko NOT FOUND (may be built-in)"
    fi
done

# FUSE module (for tokimo-sandbox-fuse — current dynamic-mount transport).
for mod in fuse; do
    P=$(find "$EXTRACT" -path '*/modules/*' -name "${mod}.ko*" | head -1 || true)
    if [ -n "$P" ]; then
        echo "==> fuse module: $P"
        cp "$P" "$EXTRAS/"
    else
        echo "==> fuse module: ${mod}.ko NOT FOUND (may be built-in)"
    fi
done

# --- 4. Rebake initrd -------------------------------------------------
echo "==> rebake initrd"
bash /src/packaging/vm/scripts/rebake-initrd.sh \
    --base       /src/packaging/vm-base/tokimo-os-arm64/initrd.img \
    --init-bin   "$INIT_BIN" \
    --init-sh    /src/packaging/vm-base/init.sh \
    --tun-pump-bin "$PUMP_BIN" \
    --fuse-bin   "$FUSE_BIN" \
    --extras-dir "$EXTRAS" \
    --out        /src/packaging/vm-base/tokimo-os-arm64/initrd.img.new

mv /src/packaging/vm-base/tokimo-os-arm64/initrd.img.new \
   /src/packaging/vm-base/tokimo-os-arm64/initrd.img
echo "==> wrote $(stat -c%s /src/packaging/vm-base/tokimo-os-arm64/initrd.img) bytes"
