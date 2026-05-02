#!/bin/sh
# Cargo runner for macOS: applies the com.apple.security.virtualization
# entitlement (ad-hoc signed) before exec'ing the binary. Required for any
# binary that calls Virtualization.framework (`arcbox-vz`).
set -eu

BIN="$1"
shift

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENT="$REPO_DIR/vz.entitlements"

if [ -f "$ENT" ] && [ -x "$BIN" ]; then
    codesign --force --sign - --entitlements "$ENT" "$BIN" >/dev/null 2>&1 || true
fi

exec "$BIN" "$@"
