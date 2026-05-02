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
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/vmlinuz"    vm/vmlinuz
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/initrd.img" vm/initrd.img
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/rootfs"     vm/rootfs
```

Override with `TOKIMO_VM_DIR=/path/to/dir` if needed.

### 2. Register the codesign cargo runner

`cargo test` on Apple Silicon needs every test/example binary ad-hoc-signed
with `packaging/macos/vz.entitlements` before exec. A helper is checked in at
`scripts/macos/codesign-and-run.sh`. Wire it up via your **local** (gitignored)
`.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"

[target.x86_64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"
```

Or invoke it manually:

```sh
codesign --force --sign - --entitlements packaging/macos/vz.entitlements \
  target/debug/deps/sandbox_integration-*
```

## Running the suite

```sh
cargo test --test sandbox_integration -- --test-threads=1
```

`--test-threads=1` is required: the apple Virtualization.framework dispatch
queue does not tolerate parallel `vm.start()` calls from a single process,
and the integration suite shares one process.

## Known limitation: reverse-mount on macOS

`add_mount(host_path → guest_path, rw)` followed by guest writes that the
host expects to read back **does not work on macOS**, by design.

### Why

Apple's Virtualization.framework freezes a `VZVirtualMachine`'s
`directorySharingDevices` snapshot at `vm.start()`. None of the
runtime-mutation paths reach the guest:

| Attempted path | Outcome |
|---|---|
| `[VZMultipleDirectoryShare.directories setObject:forKey:]` | getter returns immutable `__NSDictionary0`; raises `NSInvalidArgumentException` |
| `[VZMultipleDirectoryShare setDirectories:]` | selector does not exist (Swift `var` does not generate an Obj-C setter) |
| KVC `setValue:forKey:@"directories"` | succeeds silently; framework does not re-read the ivar |
| `[VZVirtioFileSystemDevice setShare:newShare]` after `vm.start()` | causes `vm.start()` to abort with `SIGTRAP` once the new share is observed |
| Symlinks pointing outside the share root | refused by Apple's virtio-fs sandbox |

The macOS implementation therefore uses an **APFS clone** into a
boot-time `tokimo_dyn` shared directory: `add_mount` copies (via APFS
copy-on-write) the host path into the per-session `dyn-root` subdir that
is already shared with the guest. This is **forward-only**: writes inside
the guest go to the cloned subdir, not back to the original host path.

### Practical consequence

If your code relies on bidirectional shares for runtime-added mounts,
declare them in `ConfigureParams.mounts` instead so they are wired up at
boot time as separate `VZSingleDirectoryShare` devices (which DO
propagate writes both ways).

The integration test
`add_user_with_reverse_mount_writes_to_host` is `#[cfg_attr(target_os =
"macos", ignore = ...)]` for this reason. Linux and Windows backends
have no equivalent restriction.
