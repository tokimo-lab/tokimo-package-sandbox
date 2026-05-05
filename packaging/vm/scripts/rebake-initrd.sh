#!/usr/bin/env bash
# rebake-initrd.sh — fast initrd rebuild for the dev/CI loop.
#
# Takes a "base" initrd.img (cpio.gz produced by packaging/vm-base/build.sh
# in CI) and three musl-static guest binaries, and produces a new initrd
# with /init + /bin/tokimo-sandbox-init + /bin/tokimo-tun-pump +
# /bin/tokimo-sandbox-fuse swapped in.
#
# Scope (intentionally narrow):
#   * REPLACE /init (shell script)
#   * REPLACE the three guest binaries under /bin/
#   * NEVER touch /modules/ — kernel modules including tun.ko are baked
#     into the base initrd by build.sh against the actual shipped kernel
#     and must keep their vermagic. Local dev never has the matching
#     kernel-headers around to rebuild them.
#
# The repack uses --reproducible cpio + sorted file list + gzip -n so the
# same inputs produce a byte-identical initrd.
#
# Optional safety net: if TOKIMO_EXPECTED_VERMAGIC is set in the env, we
# extract /modules/hv_vmbus.ko from the just-built initrd, read its
# vermagic via modinfo, and abort if it doesn't match. Either way we
# always print the vermagic as the last line so callers can sanity-check.
#
# Usage:
#   rebake-initrd.sh \
#       --base         <base-initrd.img> \
#       --init-bin     <path/tokimo-sandbox-init> \
#       --tun-pump-bin <path/tokimo-tun-pump> \
#       --fuse-bin     <path/tokimo-sandbox-fuse> \
#       --init-sh      <path/init.sh> \
#       --out          <out.img>

set -euo pipefail

BASE=""
INIT_BIN=""
INIT_SH=""
TUN_PUMP_BIN=""
FUSE_BIN=""
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --base)         BASE="$2";         shift 2 ;;
        --init-bin)     INIT_BIN="$2";     shift 2 ;;
        --init-sh)      INIT_SH="$2";      shift 2 ;;
        --tun-pump-bin) TUN_PUMP_BIN="$2"; shift 2 ;;
        --fuse-bin)     FUSE_BIN="$2";     shift 2 ;;
        --out)          OUT="$2";          shift 2 ;;
        -h|--help)
            sed -n '2,32p' "$0"
            exit 0
            ;;
        *)
            echo "rebake-initrd: unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

require_arg() {
    local val="$1" name="$2"
    [ -n "$val" ] || { echo "rebake-initrd: $name required" >&2; exit 2; }
}

require_arg "$BASE"         "--base"
require_arg "$INIT_BIN"     "--init-bin"
require_arg "$TUN_PUMP_BIN" "--tun-pump-bin"
require_arg "$FUSE_BIN"     "--fuse-bin"
require_arg "$INIT_SH"      "--init-sh"
require_arg "$OUT"          "--out"

[ -f "$BASE" ]          || { echo "rebake-initrd: base not found: $BASE"           >&2; exit 1; }
[ -x "$INIT_BIN" ]      || { echo "rebake-initrd: init bin not executable: $INIT_BIN" >&2; exit 1; }
[ -x "$TUN_PUMP_BIN" ]  || { echo "rebake-initrd: tun-pump bin not executable: $TUN_PUMP_BIN" >&2; exit 1; }
[ -x "$FUSE_BIN" ]      || { echo "rebake-initrd: fuse bin not executable: $FUSE_BIN"        >&2; exit 1; }
[ -f "$INIT_SH" ]       || { echo "rebake-initrd: init.sh not found: $INIT_SH"     >&2; exit 1; }

for tool in cpio gzip gunzip find install; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "rebake-initrd: missing $tool" >&2
        exit 1
    }
done

TMP="$(mktemp -d)"
VERIFY_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP" "$VERIFY_DIR"; }
trap cleanup EXIT

echo "==> rebake: extracting $BASE"
gunzip -c "$BASE" | ( cd "$TMP" && cpio -idm --quiet )

mkdir -p "$TMP/bin"

echo "==> rebake: replacing /init from $INIT_SH ($(stat -c%s "$INIT_SH") bytes)"
install -m 0755 "$INIT_SH" "$TMP/init"

echo "==> rebake: installing /bin/tokimo-sandbox-init ($(stat -c%s "$INIT_BIN") bytes)"
install -m 0755 "$INIT_BIN" "$TMP/bin/tokimo-sandbox-init"

echo "==> rebake: installing /bin/tokimo-tun-pump ($(stat -c%s "$TUN_PUMP_BIN") bytes)"
install -m 0755 "$TUN_PUMP_BIN" "$TMP/bin/tokimo-tun-pump"

echo "==> rebake: installing /bin/tokimo-sandbox-fuse ($(stat -c%s "$FUSE_BIN") bytes)"
install -m 0755 "$FUSE_BIN" "$TMP/bin/tokimo-sandbox-fuse"

OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"

echo "==> rebake: repacking -> $OUT"
( cd "$TMP" && find . -mindepth 1 | LC_ALL=C sort \
    | cpio -o -H newc --quiet --reproducible ) \
    | gzip -9 -n > "$OUT"

echo "==> rebake: done ($(stat -c%s "$OUT") bytes)"

# --- vermagic self-check -----------------------------------------------
# Extract one canonical module from the repacked initrd and read its
# vermagic. We try hv_vmbus.ko first (Windows/Hyper-V guest path), then
# virtio_net.ko (macOS VZ arm64), then any *.ko present.
gunzip -c "$OUT" | ( cd "$VERIFY_DIR" && cpio -idm --quiet )

VERMAGIC_MOD=""
for cand in "$VERIFY_DIR/modules/hv_vmbus.ko" "$VERIFY_DIR/modules/virtio_net.ko"; do
    if [ -f "$cand" ]; then
        VERMAGIC_MOD="$cand"
        break
    fi
done
if [ -z "$VERMAGIC_MOD" ] && [ -d "$VERIFY_DIR/modules" ]; then
    VERMAGIC_MOD="$(find "$VERIFY_DIR/modules" -maxdepth 1 -name '*.ko' -print 2>/dev/null | head -n 1 || true)"
fi

if [ -z "$VERMAGIC_MOD" ]; then
    echo "==> rebake: WARNING — no kernel modules in initrd; cannot self-check vermagic" >&2
    echo "==> rebake: vermagic = <unknown>"
    exit 0
fi

if command -v modinfo >/dev/null 2>&1; then
    VERMAGIC="$(modinfo -F vermagic "$VERMAGIC_MOD" 2>/dev/null || true)"
else
    # Fallback: scan the .modinfo section directly via `strings`.
    VERMAGIC="$(strings "$VERMAGIC_MOD" 2>/dev/null \
        | grep -m1 '^vermagic=' \
        | sed 's/^vermagic=//' \
        || true)"
fi
VERMAGIC="${VERMAGIC:-<unknown>}"
echo "==> rebake: vermagic = $VERMAGIC"

if [ -n "${TOKIMO_EXPECTED_VERMAGIC:-}" ]; then
    # vermagic looks like "6.12.85+deb13-amd64 SMP preempt mod_unload modversions";
    # we only compare the kernel release portion (first whitespace-delimited token).
    ACTUAL_KREL="${VERMAGIC%% *}"
    EXPECTED_KREL="${TOKIMO_EXPECTED_VERMAGIC%% *}"
    if [ "$ACTUAL_KREL" != "$EXPECTED_KREL" ]; then
        echo "==> rebake: ERROR — vermagic mismatch:" >&2
        echo "    expected: $EXPECTED_KREL" >&2
        echo "    actual:   $ACTUAL_KREL"   >&2
        exit 1
    fi
fi
