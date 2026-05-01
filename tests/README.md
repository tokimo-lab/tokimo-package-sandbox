# Integration tests

Cross-cutting tests for the public `Sandbox` API live in
[sandbox_integration.rs](sandbox_integration.rs). They exercise the **real**
guest VM (or sandbox process) on each platform — no mocks, no in-process
fakes.

The test file itself is **platform-agnostic source** (it only depends on the
public crate API), but the runtime requirements differ per OS. **Each
platform owner is responsible for porting and maintaining their own
test runner script under `scripts/`.** Currently only Windows has one.

## Windows

### Hard requirements

| Requirement | Why |
|---|---|
| **Administrator** | HCS / HCN (Hyper-V Host Compute Service / Network) require SYSTEM-level access. The library connects to `\\.\pipe\tokimo-sandbox-svc` which is owned by the SYSTEM-level service. |
| **Hyper-V feature enabled** | `Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All` must report `Enabled`. |
| **PowerShell 7 (`pwsh.exe`)** | The wrapper script uses strict mode and fails on `cargo`'s stderr-on-success under Windows PowerShell 5.1 (`$ErrorActionPreference='Stop'` + `NativeCommandError`). PS 7 handles it correctly. Path: `C:\Program Files\PowerShell\7\pwsh.exe`. |
| **VM artifacts in `vm/`** | `vm/vmlinuz`, `vm/initrd.img`, `vm/rootfs.vhdx` must exist. Pull via `pwsh scripts/fetch-vm.ps1`. |
| **`tokimo-sandbox-svc` running** | Either as an installed service (`tokimo-sandbox-svc.exe --install`) or in console mode (`tokimo-sandbox-svc.exe --console`). The runner script auto-launches console mode when needed. |
| **WAN NIC `Forwarding=Enabled`** | Required for `network_allow_all_has_nic`. HCN's NAT network only enables IP forwarding on its own `vEthernet (tokimo-sandbox-nat)` adapter; the host's WAN-facing physical NIC defaults to `Forwarding=Disabled`, which causes reverse-NAT'd return packets to be misrouted out the WAN instead of into the NAT vSwitch. The guest then never sees a SYN-ACK and `bash exec 3<>/dev/tcp/...` hangs past 5 s with probe text `NET_PROBE_DONE`. Fix (elevated, one-shot, no reboot): `Set-NetIPInterface -InterfaceAlias '<WAN-alias>' -Forwarding Enabled`. See [docs/network-allow-all-failure-investigation.md](../docs/network-allow-all-failure-investigation.md) for the full pktmon trace. |

### Run

```powershell
# From repo root, in any shell (the script self-elevates).
pwsh scripts\test-integration.ps1
```

The script:

1. Builds `tokimo-sandbox-svc.exe` and the integration test binary.
2. Self-elevates via `Start-Process -Verb RunAs` with `pwsh.exe`.
3. Launches `tokimo-sandbox-svc.exe --console` (logs → `target/integration/svc.log`).
4. Runs `cargo test --test sandbox_integration` (logs → `target/integration/test.log`).
5. Cleans up the service process.

Direct invocation (skip the wrapper, e.g. when you already have the service
running and an elevated terminal):

```powershell
cargo test --test sandbox_integration -- --nocapture
```

To run a single test:

```powershell
cargo test --test sandbox_integration <test_name> -- --nocapture
```

### Debug artefacts

| Path | Content |
|---|---|
| `target/integration/test.log` | Last `cargo test` output (test results) |
| `target/integration/svc.log` | Last service console-mode stdout |
| `C:\tokimo-debug\last-vm-com2.log` | Last guest kernel kmsg (COM2) |
| `C:\tokimo-debug\last-vm-tunnel.log` | Last init-control tunnel byte log |

### Test inventory

16 tests, all currently green (~45 s wall):

| # | Name | What it asserts |
|---|------|-----------------|
| 1 | `lifecycle_start_and_stop` | `configure → start_vm → stop_vm` round-trip clean |
| 2 | `shell_id_before_start` | `shell_id()` errors before `start_vm` |
| 3 | `shell_id_after_stop_is_error` | `shell_id()` errors after `stop_vm` |
| 4 | `shell_stdout_echo` | `write_stdin("echo X\n")` → guest emits `X` on the event stream |
| 5 | `shell_runs_multiple_commands` | `pwd` / `uname -a` / `id` output captured |
| 6 | `plan9_host_file_visible_in_guest` | Host writes sentinel file → guest `cat` returns same bytes (real I/O) |
| 7 | `status_rpcs_during_blocking_shell` | `status()` returns under load (5 calls in <2 s while shell is busy) |
| 8 | `multi_session_concurrent` | Two parallel sessions each run a marker — no cross-talk |
| 9 | `plan9_dynamic_add_remove` | `add_plan9_share` after start exposes content; `remove_plan9_share` retracts it |
| 10 | `signal_shell_delivers_sigint` | `signal_shell(boot, 2)` produces `Event::Exit { signal: Some(2) }` for the boot shell |
| 11 | `network_blocked_only_loopback` | `NetworkPolicy::Blocked` → `/sys/class/net/` only `lo`; bash `/dev/tcp/1.1.1.1/53` times out |
| 12 | `network_allow_all_has_nic` | `NetworkPolicy::AllowAll` → non-`lo` NIC enumerated **and** `bash exec 3<>/dev/tcp/1.1.1.1/53` succeeds (cross-platform egress capability check; the previous Windows-only HCN 192.168.127.0/24 subnet assertion was dropped so Linux bwrap + macOS VZ pass without backend-specific carve-outs) |
| 13 | `concurrent_commands_in_single_shell` | `(sleep 2; echo A) & (sleep 5; echo B) & wait` finishes in <7 s wall (parallel, not sequential) and both stdout markers appear |
| 14 | `multi_shell_isolated_streams` | `spawn_shell()` yields a fresh `JobId`; `write_stdin` to two shells produces stdout events tagged correctly — neither stream leaks the other's marker |
| 15 | `multi_shell_independent_signals` | `signal_shell(A, SIGINT)` kills only A; B remains responsive (`echo` round-trip) until `close_shell(B)` |
| 16 | `list_shells_tracks_lifecycle` | `list_shells()` reports `[boot]` initially; grows to 3 after two `spawn_shell()`; shrinks after `close_shell()` — set ops are synchronous, no event wait needed |

### Cross-platform portability of the test source

The file uses only public API types. Caveats per backend:

- **`Plan9Share`**: on Windows this maps to plan9-over-vsock (real shared
  filesystem). Linux (bwrap) uses `--bind host_path guest_path` (or a
  runtime `AddMountFd` for dynamic shares). macOS uses two virtio-fs
  share devices (a static `work` tag and a dynamic `tokimo_dyn` pool
  bind-mounted inside the guest). All three backends honor the same
  `Plan9Share { name, host_path, guest_path }` contract — tests 6 and
  9 are written against observable behavior, not a specific transport.
- **`NetworkPolicy::AllowAll`**: each backend chooses its own egress
  path (Windows HCN NAT, Linux shared host netns, macOS bridged NAT
  via vmnet). Test 12 only asserts capability — link enumeration plus
  outbound TCP to `1.1.1.1:53`.
- **`NetworkPolicy::Blocked`**: Windows simply omits the `NetworkAdapter`
  device from the HCS schema — kernel sees no NIC. macOS does the same
  (omits `VZNetworkDeviceConfiguration` from the VM config). Linux
  (bwrap with `--unshare-net`) achieves the same observable result via
  a fresh netns.
- **`signal_shell` / `interrupt_shell`**: relies on init delivering SIGINT
  via `killpg`. The wire path is shared across backends — should port
  directly.

## Linux

### Hard requirements

| Requirement | Why |
|---|---|
| **`bwrap`** in `$PATH` | The Linux backend wraps `bubblewrap`. `apt install bubblewrap` (Debian/Ubuntu) or `dnf install bubblewrap` (Fedora). |
| **Unprivileged user namespaces enabled** | Most distros default to enabled. If `unshare -U true` fails, set `kernel.unprivileged_userns_clone=1` and on Ubuntu 24.04+ make sure AppArmor doesn't block it. |
| **`tokimo-sandbox-init` binary on PATH** | The host backend execs it as PID 2 inside bwrap. The test invocation below puts `target/debug/` on PATH so a normal `cargo build` is enough. |
| **No service / no admin** | Unlike Windows, the Linux backend is library-only — `Sandbox::connect()` is a no-op handshake. No SCM, no daemon. |

### Run

```bash
# From repo root.
cargo build --bin tokimo-sandbox-init
PATH="$PWD/target/debug:$PATH" cargo test --test sandbox_integration -- --test-threads=1
```

`--test-threads=1` is recommended (each test spawns its own bwrap +
init pair; the bwrap default user-namespace creation rate is
self-throttling under heavy parallelism).

### Backend implementation notes

The Linux backend lives in `src/linux/`. Cross-cutting decisions worth
knowing when porting tests or debugging:

- **Mount story.** Plan9 / virtio-fs are unavailable outside a VM, so
  `Plan9Share { host_path, guest_path }` is implemented as a `bwrap`
  bind mount (`--bind host_path guest_path`). Capabilities and tests
  6 / 9 (host file visible in guest, dynamic add/remove) work because
  init holds `CAP_SYS_ADMIN` over the user-namespace and can issue
  runtime `mount(2)` calls via the `AddMountFd` op. Same observable
  semantics as Windows plan9, different mechanism.
- **`/sys` is policy-aware.**
  * `AllowAll` → host `/sys` is bind-mounted read-only (the netns is
    shared, so the host NIC list is the correct view).
  * `Blocked`  → bwrap creates an empty `/sys` and init mounts a
    fresh `sysfs` from inside the new netns. A bind mount cannot
    replace this: sysfs filtering of `/sys/class/net` is per-mount,
    not per-task. Init keys off `TOKIMO_SANDBOX_MOUNT_SYSFS=1` set
    by the host.
- **Network policy.**
  * `AllowAll` → no `--unshare-net`; full host network access. Egress
    test 12 hits `1.1.1.1:53` directly.
  * `Blocked`  → `--unshare-net`; init brings up `lo` (the
    `SIOCSIFFLAGS Operation not permitted` warning is benign, `lo`
    exists in a fresh netns regardless of explicit ifup).
- **Init transport.** Linux uses Unix `SOCK_SEQPACKET` over
  `socketpair`; bwrap inherits the child end (`pre_exec` clears
  `CLOEXEC`). `TOKIMO_SANDBOX_CONTROL_FD=<n>` tells init which fd to
  read from. macOS / Windows use VSOCK streams instead.
- **PID-1 quirk.** Init runs as PID 2 (bwrap is PID 1). The strict
  PID-1 check in `InitClient::hello()` is bypassed via
  `TOKIMO_SANDBOX_ALLOW_NON_PID1=1`, set unconditionally by the
  Linux backend. The check is meaningful only for VM-mode backends.
- **`SAFEBOX_DISABLE=1`.** Bypasses the sandbox entirely and runs
  natively. Useful for triaging "is it the test or the sandbox?"
  failures locally; never set in CI.

## macOS

### Hard requirements

| Requirement | Why |
|---|---|
| **Apple Silicon (arm64) host** | The bundled prebuilt rootfs / kernel under `packaging/vm-image/tokimo-os-arm64/` is arm64-only. |
| **macOS 13+** | Apple Virtualization.framework's modern `VZVirtioFileSystemDevice` + virtio-vsock support. |
| **Code-signed binary with `vz.entitlements`** | Without `com.apple.security.virtualization`, `start_vm()` fails with: *"The process doesn't have the com.apple.security.virtualization entitlement."* |
| **VM artifacts at `<repo>/vm/`** | The backend walks up from cwd looking for `vm/{vmlinuz,initrd.img,rootfs}` (override with `TOKIMO_VM_DIR`). |
| **No service / no admin** | Like Linux, the macOS backend is library-only — `Sandbox::connect()` is a no-op. The host process directly drives `arcbox-vz` → Virtualization.framework. |

### One-time setup

```sh
# 1. Symlink prebuilt artifacts into vm/
mkdir -p vm
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/vmlinuz"    vm/vmlinuz
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/initrd.img" vm/initrd.img
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/rootfs"     vm/rootfs

# 2. Wire up the codesign cargo runner in your local .cargo/config.toml
#    (gitignored). It ad-hoc-signs every test/example binary with
#    vz.entitlements before exec.
cat > .cargo/config.toml <<'EOF'
[target.aarch64-apple-darwin]
runner = "scripts/codesign-and-run.sh"

[target.x86_64-apple-darwin]
runner = "scripts/codesign-and-run.sh"
EOF
```

See [`docs/macos-testing.md`](../docs/macos-testing.md) for full details.

### Run

```sh
cargo test --test sandbox_integration -- --test-threads=1
```

`--test-threads=1` is required: the VZ dispatch queue does not tolerate
parallel `vm.start()` calls from a single process. The macOS backend
also takes a process-wide `BOOT_LOCK` mutex around `vm.build()` /
`vm.start()`, but the integration suite shares one host process, so
parallel test threads would still serialize on it and time out.

To run a single test:

```sh
cargo test --test sandbox_integration <test_name> -- --test-threads=1 --nocapture
```

### Backend implementation notes

The macOS backend lives in `src/macos/`. Cross-cutting decisions worth
knowing when porting tests or debugging:

- **Mount story.** `Plan9Share { host_path, guest_path }` is **not**
  implemented over Plan9. macOS uses two virtio-fs share devices:
  - `tag="work"` — read-only host workspace tree (the per-Sandbox
    `session_dir` lives under `~/.tokimo/sessions/...`).
  - `tag="tokimo_dyn"` — a per-session dynamic pool mounted at
    `/__tokimo_dyn` inside the guest. `add_plan9_share` /
    `remove_plan9_share` create/destroy bind mounts inside this pool
    via init RPCs, exposing the same `host_path → guest_path` contract
    as the Windows Plan9-over-vsock backend. The transport differs
    (virtio-fs vs Plan9), but tests 6 and 9 pass because they target
    observable behavior.
- **Network policy.**
  * `AllowAll` → `VZNetworkDeviceConfiguration::nat()` (vmnet-backed).
    vmnet hands out a runtime-chosen subnet (typically
    `192.168.64.0/24`), which does **not** match the
    `192.168.127.0/24` that `init.sh` hard-codes for Hyper-V. After the
    init handshake, the backend therefore runs busybox `udhcpc` inside
    the guest (with an inline `/tmp/udhcpc.sh` lease-apply script) to
    pick up the actual lease + default route. Only then does test 12's
    egress to `1.1.1.1:53` succeed.
  * `Blocked` → no `NetworkDeviceConfiguration` is added to the VM
    config. The guest sees no NIC at all (analogous to Windows
    omitting the HCS NetworkAdapter device).
- **Init transport.** macOS uses `VZVirtioSocketDevice` (virtio-vsock)
  on port `2222`. Same wire protocol as Windows / Linux init.
- **Process-wide `BOOT_LOCK`.** A `OnceLock<Mutex<()>>` in
  `src/macos/vm.rs` serializes `vm_cfg.build()` + `vm.start().await`
  across all `Sandbox` handles in the same host process. Without it,
  concurrent VM creation produces sporadic *"Start operation
  cancelled"* errors from the VZ dispatch queue.
- **Per-Sandbox `session_dir`.** Each handle sanitizes
  `user_data_name`, mixes in `session_id`, the host pid, and an atomic
  counter. This makes `multi_session_concurrent` collision-free even
  when callers reuse the same `user_data_name`.
- **PID-1 quirk.** Like Linux, the guest is fully chrooted by
  `init.sh` before `tokimo-sandbox-init` runs, and init hits the same
  `TOKIMO_SANDBOX_PRE_CHROOTED=1` shortcut to skip its own
  mount/chroot setup. The strict PID-1 handshake check is satisfied
  natively because init really is PID 1 inside the guest.

### Test inventory

All 16 tests pass (~25 s wall on M-series, single-threaded). The
inventory is identical to the Windows table above; behavioral
differences are limited to the mount mechanism (virtio-fs not Plan9)
and the egress path (vmnet NAT not HCN NAT).

## Editing tests

Conventions used by the existing suite:

- Helper `config(label)` builds a `ConfigureParams` with a unique
  `session_id = "{pid}-{label}-{counter}"` to avoid collisions when tests
  run in parallel.
- Helper `drain_until(rx, shell, needle, timeout)` collects stdout bytes
  from the event stream until either `needle` appears or `timeout` elapses.
  Use a per-test 4-byte sentinel suffix (e.g. `LC_DONE_X9F2`) to avoid
  cross-contamination if helpers are reused.
- Network probes use `bash exec 3<>/dev/tcp/<ip>/<port>` rather than
  `curl`/`wget` — `bash` is the only shell guaranteed to be in the rootfs
  PATH when the chroot is entered without a login shell.
- Use `/sys/class/net/` over `ip link show` — the `iproute2` tools live in
  `/sbin` which is **not** in the chroot's default PATH.
