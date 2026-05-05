#!/usr/bin/env bash
# rebake-initrd.sh — local dev convenience for rebuilding vm/initrd.img
# on macOS. Identical to scripts/linux/rebake-initrd.sh.
#
# Note: guest binaries are always Linux musl, never aarch64-apple-darwin.
# macOS toolchains can cross-compile to {x86_64,aarch64}-unknown-linux-musl
# directly (`rustup target add` + the musl-cross homebrew formula handles
# the linker), so we don't need a Docker shim.
exec bash "$(cd "$(dirname "$0")/../linux" && pwd)/rebake-initrd.sh" "$@"
