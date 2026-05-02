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

## Dynamic mounts use NFSv3, not virtio-fs

As of the macOS-NFS-mount rewrite, both boot-time and runtime
`add_mount` shares are exposed to the guest over a single in-process
NFSv3 server (`nfsserve` crate) bound to `127.0.0.1`. The guest reaches
it through the always-on smoltcp gateway at `192.168.127.1:2049`, which
the netstack splices to the loopback NFS port via a registered
`LocalService`.

Each share is a virtual subtree under the export root; the guest mounts
them as `192.168.127.1:/<name> -> /<guest_path>` with
`nolock,vers=3,proto=tcp,hard`. `remove_mount` issues `umount2(MNT_DETACH)`
in the guest and tombstones the slot host-side.

This replaces the previous virtio-fs + APFS-clone approach. **Reverse
mounts now work bidirectionally on macOS**: guest writes to a
`rw` share land directly in the host path, just like Linux/Windows. The
integration test `add_user_with_reverse_mount_writes_to_host` is no
longer ignored on macOS.

`EgressPolicy::Blocked` still blocks all upstream traffic; the netstack's
`LocalService` table is exempt so NFS keeps working under either policy.
