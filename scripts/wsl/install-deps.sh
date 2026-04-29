#!/usr/bin/env bash
# 一次性安装 WSL 构建依赖 (only musl-tools needed).
# 在 WSL Ubuntu 中以 sudo 运行：
#   sudo bash scripts/wsl/install-deps.sh
set -e
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q musl-tools
echo "musl-tools installed."
