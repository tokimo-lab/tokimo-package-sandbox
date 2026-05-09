#!/usr/bin/env bash
# fetch-busybox.sh — fetch a statically-linked busybox binary for use in the
# microVM initrd.
#
# Uses the official `busybox:musl` Docker image (static-pie linked, x86-64).
# The binary is placed in target/initrd-deps/busybox and never committed to git
# (target/ is in .gitignore).
#
# Usage:
#   ./scripts/linux/fetch-busybox.sh [out-path]
#
# Default out-path: target/initrd-deps/busybox
set -euo pipefail

OUT="${1:-target/initrd-deps/busybox}"
mkdir -p "$(dirname "$OUT")"

if [ -f "$OUT" ]; then
    echo "fetch-busybox: already present at $OUT ($(du -sh "$OUT" | cut -f1)), skipping."
    exit 0
fi

echo "fetch-busybox: pulling busybox:musl via docker..."
docker pull busybox:musl 2>&1 | tail -2

docker run --rm --entrypoint /bin/cat busybox:musl /bin/busybox > "$OUT"
chmod +x "$OUT"

# Verify it is not dynamically linked (static or static-pie are both OK).
if command -v file &>/dev/null; then
    file_out=$(file "$OUT")
    echo "fetch-busybox: $file_out"
    if echo "$file_out" | grep -q "dynamically linked"; then
        echo "fetch-busybox: ERROR: binary is dynamically linked — cannot use in bare initrd" >&2
        rm -f "$OUT"
        exit 1
    fi
fi

echo "fetch-busybox: done: $OUT ($(du -sh "$OUT" | cut -f1))"
