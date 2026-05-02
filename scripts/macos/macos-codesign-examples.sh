#!/bin/sh
# Apply the com.apple.security.virtualization entitlement (ad-hoc signed)
# to every macOS example binary so they can call Virtualization.framework.
#
# Run this after `cargo build --examples [--release]`.

set -eu

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENT="$REPO_DIR/vz.entitlements"

if [ ! -f "$ENT" ]; then
    echo "error: $ENT not found" >&2
    exit 1
fi

sign_one() {
    bin="$1"
    if [ -x "$bin" ]; then
        echo "codesign $bin"
        codesign --force --sign - --entitlements "$ENT" "$bin"
    fi
}

for profile in debug release; do
    for ex in smoke dynamic_mount network_check; do
        sign_one "$REPO_DIR/target/$profile/examples/$ex"
    done
done
