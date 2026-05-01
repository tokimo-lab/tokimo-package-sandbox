# Running tests on macOS

The macOS backend boots a Linux micro-VM via Apple Virtualization.framework
(`arcbox-vz`). The framework requires the `com.apple.security.virtualization`
entitlement on the calling binary — without it `start_vm()` fails with:

```
Invalid virtual machine configuration. The process doesn't have the
"com.apple.security.virtualization" entitlement.
```

## One-time setup

### 1. Provide VM artifacts at `<repo>/vm/`

The backend auto-discovers `vmlinuz`, `initrd.img`, and `rootfs/` under
`<repo>/vm/` (or any ancestor). For local development point those at the
prebuilt arm64 artifacts:

```sh
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/vmlinuz"    vm/vmlinuz
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/initrd.img" vm/initrd.img
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/rootfs"     vm/rootfs
```

Override with `TOKIMO_VM_DIR=/path/to/dir` if needed.

### 2. Register the codesign cargo runner

`cargo test` on Apple Silicon needs every test/example binary ad-hoc-signed
with `vz.entitlements` before exec. A helper is checked in at
`scripts/codesign-and-run.sh`. Wire it up via your **local** (gitignored)
`.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
runner = "scripts/codesign-and-run.sh"

[target.x86_64-apple-darwin]
runner = "scripts/codesign-and-run.sh"
```

Or invoke it manually:

```sh
codesign --force --sign - --entitlements vz.entitlements \
  target/debug/deps/sandbox_integration-*
```

## Running the suite

```sh
cargo test --test sandbox_integration -- --test-threads=1
```

`--test-threads=1` is required: the apple Virtualization.framework dispatch
queue does not tolerate parallel `vm.start()` calls from a single process,
and the integration suite shares one process.
