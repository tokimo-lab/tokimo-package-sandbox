#!/usr/bin/env bash
# Fetch the ch (cloud-hypervisor) backend runtime dependencies into bin/.
#
# Layout produced:
#   bin/cloud-hypervisor/<ver>/bin/cloud-hypervisor
#   bin/cloud-hypervisor/<ver>/bin/ch-remote
#   bin/cloud-hypervisor/current                          → ./<ver>     (symlink)
#   bin/virtiofsd/<ver>/virtiofsd
#   bin/virtiofsd/<ver>/LICENSE-APACHE
#   bin/virtiofsd/<ver>/LICENSE-BSD-3-Clause
#   bin/virtiofsd/current                                 → ./<ver>     (symlink)
#
# The ch backend reuses the same Debian generic vmlinuz bzImage that
# ships in the vm-kernel-* release (fetched by scripts/linux/fetch-vm.sh).
# cloud-hypervisor v36+ accepts bzImage, and the initrd loads
# vmw_vsock_virtio_transport early so vsock works without a custom kernel.
#
# Sources:
#   cloud-hypervisor → upstream cloud-hypervisor/cloud-hypervisor releases
#                      (static binary `cloud-hypervisor-static` + `ch-remote-static`)
#   virtiofsd        → tokimo-lab/tokimo-package-sandbox virtiofsd-v* releases
#                      (tarball with virtiofsd + license files)
#
# Usage:
#   scripts/linux/fetch-ch-deps.sh
#   CH_VER=v51.1 VIRTIOFSD_TAG=virtiofsd-v1.13.3 scripts/linux/fetch-ch-deps.sh
#   scripts/linux/fetch-ch-deps.sh -f                # force re-download

set -euo pipefail

REPO="tokimo-lab/tokimo-package-sandbox"
CH_VER="${CH_VER:-v51.1}"
VIRTIOFSD_TAG="${VIRTIOFSD_TAG:-virtiofsd-v1.13.3}"
FORCE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force) FORCE=1; shift ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) CH_ASSET_SUFFIX="static" ; VIRTIOFSD_SFX="x86_64" ;;
    aarch64) CH_ASSET_SUFFIX="static-aarch64" ; VIRTIOFSD_SFX="arm64" ;;
    *) echo "FATAL: unsupported arch $ARCH" >&2; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

dl() {
    echo "==> downloading $(basename "$2") <- $1"
    curl -fL --retry 3 -o "$2" "$1"
}

# ---------------- cloud-hypervisor ----------------
CH_DIR="$BIN_DIR/cloud-hypervisor/$CH_VER/bin"
if [[ $FORCE -eq 1 || ! -x "$CH_DIR/cloud-hypervisor" ]]; then
    mkdir -p "$CH_DIR"
    BASE="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VER"
    dl "$BASE/cloud-hypervisor-${CH_ASSET_SUFFIX}" "$CH_DIR/cloud-hypervisor"
    dl "$BASE/ch-remote-${CH_ASSET_SUFFIX}"         "$CH_DIR/ch-remote"
    chmod +x "$CH_DIR/cloud-hypervisor" "$CH_DIR/ch-remote"
else
    echo "==> cloud-hypervisor $CH_VER already present"
fi
ln -sfn "$CH_VER" "$BIN_DIR/cloud-hypervisor/current"

# ---------------- virtiofsd ----------------
VFS_VER="${VIRTIOFSD_TAG#virtiofsd-}"
VFS_DIR="$BIN_DIR/virtiofsd/$VFS_VER"
if [[ $FORCE -eq 1 || ! -x "$VFS_DIR/virtiofsd" ]]; then
    mkdir -p "$VFS_DIR"
    URL="https://github.com/$REPO/releases/download/$VIRTIOFSD_TAG/tokimo-virtiofsd-${VIRTIOFSD_SFX}.tar.zst"
    dl "$URL" "$WORK/virtiofsd.tar.zst"
    zstd -d -f "$WORK/virtiofsd.tar.zst" -o "$WORK/virtiofsd.tar"
    tar -xf "$WORK/virtiofsd.tar" -C "$VFS_DIR"
    chmod +x "$VFS_DIR/virtiofsd"
else
    echo "==> virtiofsd $VFS_VER already present"
fi
ln -sfn "$VFS_VER" "$BIN_DIR/virtiofsd/current"

echo "==> done: $(ls -1 "$BIN_DIR" | tr '\n' ' ')"
