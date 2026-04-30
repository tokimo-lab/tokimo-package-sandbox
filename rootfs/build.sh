#!/usr/bin/env bash
# Build TokimoOS rootfs locally.
# Output: rootfs-amd64/ or rootfs-arm64/ (extracted filesystem).
# Usage: bash rootfs/build.sh [amd64|arm64]
set -euo pipefail

ARCH="${1:-${TOKIMO_ARCH:-amd64}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$PROJECT_DIR/rootfs-${ARCH}"

case "$ARCH" in
  amd64|arm64) ;;
  x86_64)  ARCH="amd64" ; OUT_DIR="$PROJECT_DIR/rootfs-amd64" ;;
  aarch64) ARCH="arm64" ; OUT_DIR="$PROJECT_DIR/rootfs-arm64" ;;
  *) echo "Unsupported arch: $ARCH (use amd64 or arm64)"; exit 1 ;;
esac

echo "==> Building rootfs for $ARCH..."
echo "    Output: $OUT_DIR"

docker buildx build \
  -f "$SCRIPT_DIR/Dockerfile" \
  --platform "linux/${ARCH}" \
  --output "type=local,dest=$OUT_DIR" \
  "$PROJECT_DIR"

echo ""
echo "Done! Rootfs at: $OUT_DIR"
echo "Size: $(du -sh "$OUT_DIR" | cut -f1)"
echo "Enter sandbox: bash rootfs/enter.sh  # sets ROOTFS_DIR=$OUT_DIR"
