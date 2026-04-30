#!/usr/bin/env bash
# Import existing rootfs into Docker, modify interactively, re-export.
# Useful for apt install etc.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS_DIR="$PROJECT_DIR/tokimo-os-amd64/rootfs"
ROOTFS_TAR="$PROJECT_DIR/rootfs.tar"
CONTAINER_NAME="tokimo-builder"
IMAGE_NAME="tokimo-modify-base"

for d in "$PROJECT_DIR"/tokimo-os-*/rootfs; do
    [ -d "$d" ] && ROOTFS_DIR="$d" && break
done

if [ ! -d "$ROOTFS_DIR/usr" ]; then
  echo "error: rootfs not found; run bash build.sh first"
  exit 1
fi

echo "==> Packing rootfs → tar..."
tar -cpf "$ROOTFS_TAR" -C "$ROOTFS_DIR" .

echo "==> Importing as Docker image..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
docker rmi -f "$IMAGE_NAME" 2>/dev/null || true
docker import "$ROOTFS_TAR" "$IMAGE_NAME"
rm -f "$ROOTFS_TAR"

echo "==> Starting interactive container (exit when done)..."
docker run -it \
  --name "$CONTAINER_NAME" \
  --platform linux/amd64 \
  "$IMAGE_NAME" bash

echo "==> Re-exporting rootfs..."
docker export "$CONTAINER_NAME" -o "$ROOTFS_TAR"
echo "    size: $(du -sh "$ROOTFS_TAR" | cut -f1)"

rm -rf "$ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR"
tar -xpf "$ROOTFS_TAR" \
  -C "$ROOTFS_DIR" \
  --numeric-owner --no-same-owner \
  --exclude='dev/*' --exclude='proc/*' --exclude='sys/*'

echo "==> Cleanup..."
docker rm -f "$CONTAINER_NAME"
docker rmi -f "$IMAGE_NAME"
rm -f "$ROOTFS_TAR"

echo "Done. Changes saved to $ROOTFS_DIR"
echo "Remember: git add -A && git commit"
