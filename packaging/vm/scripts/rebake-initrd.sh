#!/usr/bin/env bash
# rebake-initrd.sh — fast initrd rebuild for the dev/CI loop.
#
# Takes a "base" initrd.img (cpio.gz, no tokimo-sandbox-init), a freshly-built
# tokimo-sandbox-init binary (musl static), and produces a new initrd.img with
# the init binary baked in at /bin/tokimo-sandbox-init.
#
# Used by:
#   * .github/workflows/vm.yml — appends fuse binary onto build.sh's initrd
#   * scripts/rebake-initrd.{sh,ps1} — local dev iteration after editing init/
#
# Usage:
#   rebake-initrd.sh --base <base-initrd.img> --init-bin <path> --out <out.img>
#
# The repack uses --reproducible cpio + sorted file list + gzip -n so the same
# inputs produce a byte-identical initrd (helps caching downstream).

set -euo pipefail

BASE=""
INIT_BIN=""
INIT_SH=""
TUN_PUMP_BIN=""
FUSE_BIN=""
EXTRAS_DIR=""
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --base)         BASE="$2";         shift 2 ;;
        --init-bin)     INIT_BIN="$2";     shift 2 ;;
        --init-sh)      INIT_SH="$2";      shift 2 ;;
        --tun-pump-bin) TUN_PUMP_BIN="$2"; shift 2 ;;
        --fuse-bin)     FUSE_BIN="$2";     shift 2 ;;
        --extras-dir)   EXTRAS_DIR="$2";   shift 2 ;;
        --out)          OUT="$2";          shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *)
            echo "rebake-initrd: unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

[ -n "$BASE" ]     || { echo "rebake-initrd: --base required"     >&2; exit 2; }
[ -n "$INIT_BIN" ] || { echo "rebake-initrd: --init-bin required" >&2; exit 2; }
[ -n "$OUT" ]      || { echo "rebake-initrd: --out required"      >&2; exit 2; }
[ -f "$BASE" ]     || { echo "rebake-initrd: base not found: $BASE" >&2; exit 1; }
[ -x "$INIT_BIN" ] || { echo "rebake-initrd: init bin not executable: $INIT_BIN" >&2; exit 1; }
[ -z "$INIT_SH" ]  || [ -f "$INIT_SH" ] || { echo "rebake-initrd: init.sh not found: $INIT_SH" >&2; exit 1; }
[ -z "$TUN_PUMP_BIN" ] || [ -x "$TUN_PUMP_BIN" ] || { echo "rebake-initrd: tun-pump bin not executable: $TUN_PUMP_BIN" >&2; exit 1; }
[ -z "$FUSE_BIN" ] || [ -x "$FUSE_BIN" ] || { echo "rebake-initrd: fuse bin not executable: $FUSE_BIN" >&2; exit 1; }

for tool in cpio gzip gunzip find install xz; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "rebake-initrd: missing $tool" >&2
        exit 1
    }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> rebake: extracting $BASE"
gunzip -c "$BASE" | ( cd "$TMP" && cpio -idm --quiet )

mkdir -p "$TMP/bin"
echo "==> rebake: installing init binary -> /bin/tokimo-sandbox-init ($(stat -c%s "$INIT_BIN") bytes)"
install -m 0755 "$INIT_BIN" "$TMP/bin/tokimo-sandbox-init"

if [ -n "$INIT_SH" ]; then
    echo "==> rebake: replacing /init from $INIT_SH ($(stat -c%s "$INIT_SH") bytes)"
    install -m 0755 "$INIT_SH" "$TMP/init"
fi

if [ -n "$TUN_PUMP_BIN" ]; then
    echo "==> rebake: installing tun-pump -> /bin/tokimo-tun-pump ($(stat -c%s "$TUN_PUMP_BIN") bytes)"
    install -m 0755 "$TUN_PUMP_BIN" "$TMP/bin/tokimo-tun-pump"
fi

if [ -n "$FUSE_BIN" ]; then
    echo "==> rebake: installing fuse bin -> /bin/tokimo-sandbox-fuse ($(stat -c%s "$FUSE_BIN") bytes)"
    install -m 0755 "$FUSE_BIN" "$TMP/bin/tokimo-sandbox-fuse"
fi

if [ -n "$EXTRAS_DIR" ] && [ -d "$EXTRAS_DIR" ]; then
    mkdir -p "$TMP/modules"
    # Decompress any *.ko.xz extras into /modules/<name>.ko so init.sh's
    # busybox insmod (which doesn't speak xz) can load them.
    for f in "$EXTRAS_DIR"/*.ko.xz; do
        [ -f "$f" ] || continue
        name=$(basename "$f" .ko.xz)
        echo "==> rebake: decompressing extra module $name.ko.xz -> /modules/$name.ko"
        xz -dc "$f" > "$TMP/modules/$name.ko"
    done
    for f in "$EXTRAS_DIR"/*.ko; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        echo "==> rebake: installing extra module $name -> /modules/$name"
        install -m 0644 "$f" "$TMP/modules/$name"
    done
fi

OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"

echo "==> rebake: repacking -> $OUT"
( cd "$TMP" && find . -mindepth 1 | LC_ALL=C sort \
    | cpio -o -H newc --quiet --reproducible ) \
    | gzip -9 -n > "$OUT"

echo "==> rebake: done ($(stat -c%s "$OUT") bytes)"
