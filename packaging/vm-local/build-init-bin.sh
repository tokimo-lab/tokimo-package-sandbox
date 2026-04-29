#!/usr/bin/env bash
# Build tokimo-sandbox-init (musl static x86_64). Run inside rust:1.95-slim-bookworm.
set -euo pipefail
apt-get update -qq
apt-get install -y -qq musl-tools >/dev/null
rustup target add x86_64-unknown-linux-musl >/dev/null
cargo build --release --target x86_64-unknown-linux-musl --bin tokimo-sandbox-init
cp target/x86_64-unknown-linux-musl/release/tokimo-sandbox-init packaging/vm-local/tokimo-sandbox-init
chmod +x packaging/vm-local/tokimo-sandbox-init
ls -lh packaging/vm-local/tokimo-sandbox-init
