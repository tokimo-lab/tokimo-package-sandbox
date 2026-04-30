#!/usr/bin/env bash
# Enter TokimoOS rootfs sandbox via bwrap.
# Changes write directly to the rootfs directory, persist after exit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS_DIR="${ROOTFS_DIR:-$SCRIPT_DIR/../rootfs-amd64}"

if [ ! -d "$ROOTFS_DIR/usr" ]; then
  echo "Error: rootfs not found at $ROOTFS_DIR"
  echo "Build with: docker build -f $SCRIPT_DIR/Dockerfile -o type=local,dest=$ROOTFS_DIR $SCRIPT_DIR/.."
  exit 1
fi

echo "Entering TokimoOS sandbox ... (exit to leave, changes saved to $ROOTFS_DIR/)"
exec bwrap \
  --bind "$ROOTFS_DIR" / \
  --bind /tmp /tmp \
  --proc /proc \
  --dev /dev \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --unshare-user \
  --uid 1000 \
  --gid 1000 \
  --unshare-uts \
  --hostname TokimoOS \
  --unsetenv LD_LIBRARY_PATH \
  --setenv HOME /home/tokimo \
  --setenv USER tokimo \
  --setenv LOGNAME tokimo \
  --setenv TERM "${TERM:-xterm-256color}" \
  /bin/bash --login
