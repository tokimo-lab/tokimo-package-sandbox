.PHONY: initrd help

SUBMODULE_ROOT := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
# Main repository root is two levels up from the submodule.
MAIN_REPO_ROOT ?= $(realpath $(SUBMODULE_ROOT)../..)
ARCH           ?= linux-x86_64
RUST_TARGET    ?= x86_64-unknown-linux-musl
AGENT_BIN       = target/$(RUST_TARGET)/release/tokimo-guest-agent
INITRD_OUT      = $(MAIN_REPO_ROOT)/bin/ch-initrd/dev/$(ARCH)/initrd.cpio.gz
BUSYBOX_BIN     = target/initrd-deps/busybox

# zig binary: prefer $HOME/zig-x86_64-linux-0.14.1/zig, fall back to PATH.
ZIG_DIR        ?= $(HOME)/zig-x86_64-linux-0.14.1

help: ## Show available targets
	@echo "  make initrd    Build tokimo-guest-agent musl binary + pack initrd.cpio.gz"

## Build the musl static binary and pack it into an initrd.cpio.gz.
##
## Prerequisites (no sudo):
##   rustup target add x86_64-unknown-linux-musl
##   cargo install cargo-zigbuild
##   Download zig 0.14.1 to ~/zig-x86_64-linux-0.14.1/  (see scripts/linux/build-ch-initrd.sh)
##   docker (for fetching busybox:musl static binary)
##
## Output: <main-repo>/bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz
initrd: ## Build musl agent + fetch busybox + pack initrd.cpio.gz
	@echo "[initrd] fetching busybox static binary..."
	bash scripts/linux/fetch-busybox.sh "$(BUSYBOX_BIN)"
	@echo "[initrd] building tokimo-guest-agent (musl static)..."
	PATH="$(ZIG_DIR):$(PATH)" \
	    cargo-zigbuild zigbuild \
	        --release --bin tokimo-guest-agent \
	        --target $(RUST_TARGET)
	@echo "[initrd] packing initrd..."
	bash scripts/linux/build-ch-initrd.sh "$(INITRD_OUT)" "$(AGENT_BIN)" "$(BUSYBOX_BIN)"
	@echo "[initrd] done: $(INITRD_OUT)"
