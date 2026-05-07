#!/usr/bin/env bash
# rebake-initrd.sh — local dev convenience for rebuilding .vm/base/initrd.img
# after editing init.sh or the three guest-side musl binaries (init,
# tun-pump, fuse).
#
# Pipeline:
#   1. cargo build --release --target $RUST_TARGET
#         --bin tokimo-sandbox-init
#         --bin tokimo-tun-pump
#         --bin tokimo-sandbox-fuse
#   2. packaging/vm/scripts/rebake-initrd.sh \
#         --base   <BaseInitrd>     (default: .vm/base/initrd.img — must already exist)
#         --init-bin / --tun-pump-bin / --fuse-bin / --init-sh
#         --out    target/vm-rebake/initrd.img
#   3. Optional: --install-to-vm copies the rebaked initrd over .vm/base/initrd.img
#      and writes .vm/base/.rebaked so the user knows this isn't a clean release.
#
# Flags:
#   --skip-build           skip cargo build (use existing target/<triple>/release/*)
#   --install-to-vm        copy result over .vm/base/initrd.img
#   --arch amd64|arm64     target arch (default: host arch)
#   --base <path>          base initrd to rebake (default: <repo>/.vm/base/initrd.img)
#
# Note: guest binaries are always Linux musl, never the host's native
# triple (so on macOS this still cross-compiles to *-unknown-linux-musl
# rather than aarch64-apple-darwin).
set -euo pipefail

ARCH=""
SKIP_BUILD=0
INSTALL_TO_VM=0
BASE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build)     SKIP_BUILD=1;       shift ;;
        --install-to-vm)  INSTALL_TO_VM=1;    shift ;;
        --arch)           ARCH="$2";          shift 2 ;;
        --base)           BASE="$2";          shift 2 ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "rebake-initrd: unknown arg: $1" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [ -z "$ARCH" ]; then
    case "$(uname -m)" in
        x86_64)         ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *) echo "rebake-initrd: unsupported host arch $(uname -m); pass --arch" >&2; exit 2 ;;
    esac
fi
case "$ARCH" in
    amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;;
    arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "rebake-initrd: unsupported --arch $ARCH (amd64 | arm64)" >&2; exit 2 ;;
esac

[ -n "$BASE" ] || BASE="$REPO_ROOT/.vm/base/initrd.img"
[ -f "$BASE" ] || { echo "rebake-initrd: base initrd not found: $BASE (run scripts/linux/fetch-vm.sh first)" >&2; exit 1; }

INIT_BIN="$REPO_ROOT/target/$RUST_TARGET/release/tokimo-sandbox-init"
PUMP_BIN="$REPO_ROOT/target/$RUST_TARGET/release/tokimo-tun-pump"
FUSE_BIN="$REPO_ROOT/target/$RUST_TARGET/release/tokimo-sandbox-fuse"

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "==> cargo build --release --target $RUST_TARGET (init + tun-pump + fuse)"
    ( cd "$REPO_ROOT" && cargo build --release --target "$RUST_TARGET" \
        --bin tokimo-sandbox-init \
        --bin tokimo-tun-pump \
        --bin tokimo-sandbox-fuse )
fi

for f in "$INIT_BIN" "$PUMP_BIN" "$FUSE_BIN"; do
    [ -x "$f" ] || { echo "rebake-initrd: missing binary $f (drop --skip-build?)" >&2; exit 1; }
done

OUT_DIR="$REPO_ROOT/target/vm-rebake"
mkdir -p "$OUT_DIR"
OUT_IMG="$OUT_DIR/initrd.img"

bash "$REPO_ROOT/packaging/vm/scripts/rebake-initrd.sh" \
    --base         "$BASE" \
    --init-bin     "$INIT_BIN" \
    --tun-pump-bin "$PUMP_BIN" \
    --fuse-bin     "$FUSE_BIN" \
    --init-sh      "$REPO_ROOT/packaging/vm-base/init.sh" \
    --out          "$OUT_IMG"

echo "==> rebaked initrd: $OUT_IMG ($(stat -c%s "$OUT_IMG" 2>/dev/null || stat -f%z "$OUT_IMG") bytes)"

if [ "$INSTALL_TO_VM" -eq 1 ]; then
    target="$REPO_ROOT/.vm/base/initrd.img"
    cp -f "$OUT_IMG" "$target"
    echo "rebaked from $BASE at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$REPO_ROOT/.vm/base/.rebaked"
    echo "==> installed to $target (.vm/base/.rebaked marker written)"
fi
