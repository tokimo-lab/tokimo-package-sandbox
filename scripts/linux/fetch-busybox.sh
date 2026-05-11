#!/usr/bin/env bash
# fetch-busybox.sh — fetch a statically-linked busybox binary for use in the
# microVM initrd.
#
# Uses the official multi-arch `busybox:musl` Docker image (static-pie linked).
# The binary is placed in target/initrd-deps/busybox and never committed to git
# (target/ is in .gitignore).
#
# Usage:
#   ./scripts/linux/fetch-busybox.sh [out-path]
#
# Default out-path: target/initrd-deps/busybox
# Override detected Docker platform with BUSYBOX_PLATFORM=linux/amd64|linux/arm64.
set -euo pipefail

OUT="${1:-target/initrd-deps/busybox}"
mkdir -p "$(dirname "$OUT")"

if [ -f "$OUT" ]; then
    echo "fetch-busybox: already present at $OUT ($(du -sh "$OUT" | cut -f1)), skipping."
    exit 0
fi

if [ -z "${BUSYBOX_PLATFORM:-}" ]; then
    case "$(uname -m)" in
        x86_64|amd64) BUSYBOX_PLATFORM="linux/amd64" ;;
        aarch64|arm64) BUSYBOX_PLATFORM="linux/arm64" ;;
        *)
            echo "fetch-busybox: unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
fi

echo "fetch-busybox: pulling busybox:musl for $BUSYBOX_PLATFORM via docker..."
docker pull --platform "$BUSYBOX_PLATFORM" busybox:musl 2>&1 | tail -2

docker run --rm --platform "$BUSYBOX_PLATFORM" --entrypoint /bin/cat busybox:musl /bin/busybox > "$OUT"
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
