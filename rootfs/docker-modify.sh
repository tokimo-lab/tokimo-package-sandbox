#!/usr/bin/env bash
# Import rootfs into Docker for interactive modification (apt install, etc.).
# Re-exports back to rootfs directory on exit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS_DIR="$SCRIPT_DIR/../rootfs-amd64"
ROOTFS_TAR="$SCRIPT_DIR/rootfs.tar"
CONTAINER_NAME="tokimo-modify-$$"
IMAGE_NAME="tokimo-modify-base"

if [ ! -d "$ROOTFS_DIR/usr" ]; then
  echo "Error: rootfs not found at $ROOTFS_DIR"
  echo "Build with: docker build -f $SCRIPT_DIR/Dockerfile -o type=local,dest=$ROOTFS_DIR $SCRIPT_DIR/.."
  exit 1
fi

echo "==> Packing rootfs/ to tar..."
tar -cpf "$ROOTFS_TAR" -C "$ROOTFS_DIR" .

echo "==> Importing as Docker image..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
docker rmi -f "$IMAGE_NAME" 2>/dev/null || true
docker import "$ROOTFS_TAR" "$IMAGE_NAME"
rm -f "$ROOTFS_TAR"

echo "==> Starting interactive container (make your changes, then exit)..."
docker run -it \
  --name "$CONTAINER_NAME" \
  --platform linux/amd64 \
  "$IMAGE_NAME" bash

echo "==> Re-exporting rootfs..."
docker export "$CONTAINER_NAME" -o "$ROOTFS_TAR"
echo "    Size: $(du -sh "$ROOTFS_TAR" | cut -f1)"

rm -rf "$ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR"
tar -xpf "$ROOTFS_TAR" \
  -C "$ROOTFS_DIR" \
  --numeric-owner --no-same-owner \
  --exclude='dev/*' --exclude='proc/*' --exclude='sys/*'

echo "==> Cleaning up..."
docker rm -f "$CONTAINER_NAME"
docker rmi -f "$IMAGE_NAME"
rm -f "$ROOTFS_TAR"

echo "Done! Changes saved to $ROOTFS_DIR/"
echo "Remember to git add -A && git commit"
