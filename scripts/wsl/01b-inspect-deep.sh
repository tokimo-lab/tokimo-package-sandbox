#!/usr/bin/env bash
# Phase 1b: Deep inspection of Claude's initrd boot scripts
set -e
cd /tmp/tokimo-claude-inspect/initrd-extract

SEG=""
for d in seg*/; do
    [ -f "$d/init" ] && SEG="$d"
done
[ -z "$SEG" ] && { echo "no init found"; exit 1; }
echo "main seg: $SEG"
cd "$SEG"

echo ""
echo "--- /scripts/init-top/* ---"
ls scripts/init-top/ 2>/dev/null || true

echo ""
echo "--- /scripts/local-top/* ---"
ls scripts/local-top/ 2>/dev/null || true

echo ""
echo "--- /scripts/local (head 120) ---"
[ -f scripts/local ] && head -120 scripts/local

echo ""
echo "--- modules.dep grep ---"
for pat in '9p' 'hv_sock' 'hyperv' 'storvsc' 'vsock'; do
    echo "[$pat]"
    grep -E "$pat" lib/modules/6.8.0-106-generic/modules.dep 2>/dev/null | head -10 || true
done

echo ""
echo "--- conf/modules ---"
[ -f conf/modules ] && cat conf/modules

echo ""
echo "--- modules.builtin (9p/vsock/hv) ---"
grep -E '9p|vsock|hyperv|hv_' lib/modules/6.8.0-106-generic/modules.builtin 2>/dev/null | head -20 || true

echo ""
echo "--- /etc/modprobe.d ---"
ls etc/modprobe.d/ 2>/dev/null || true

echo ""
echo "--- /scripts/local-bottom ---"
ls scripts/local-bottom/ 2>/dev/null || true

echo ""
echo "--- /scripts/init-bottom ---"
ls scripts/init-bottom/ 2>/dev/null || true

echo ""
echo "--- segments: total module sizes ---"
du -sh lib/modules 2>/dev/null || true

echo ""
echo "===== seg01 (microcode-only, just confirm) ====="
ls /tmp/tokimo-claude-inspect/initrd-extract/seg01/ 2>/dev/null | head
