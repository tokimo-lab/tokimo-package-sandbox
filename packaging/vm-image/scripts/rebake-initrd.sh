#!/usr/bin/env bash
# rebake-initrd.sh — fast initrd rebuild for the dev/CI loop.
#
# Takes a "base" initrd.img (cpio.gz, no tokimo-sandbox-init), a freshly-built
# tokimo-sandbox-init binary (musl static), and produces a new initrd.img with
# the init binary baked in at /bin/tokimo-sandbox-init.
#
# Used by:
#   * .github/workflows/vm-image.yml — assembles vm-v* release from vm-base-v*
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
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --base)     BASE="$2";     shift 2 ;;
        --init-bin) INIT_BIN="$2"; shift 2 ;;
        --out)      OUT="$2";      shift 2 ;;
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

for tool in cpio gzip gunzip find install; do
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

OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"

echo "==> rebake: repacking -> $OUT"
( cd "$TMP" && find . -mindepth 1 | LC_ALL=C sort \
    | cpio -o -H newc --quiet --reproducible ) \
    | gzip -9 -n > "$OUT"

echo "==> rebake: done ($(stat -c%s "$OUT") bytes)"
