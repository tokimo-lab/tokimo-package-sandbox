# Integration tests

Cross-cutting tests for the public `Sandbox` API. They exercise the **real**
guest VM (or sandbox process) on each platform — no mocks, no in-process
fakes.

The test source is **platform-agnostic** (it only depends on the public crate
API), but the runtime requirements differ per OS. **Each platform owner is
responsible for porting and maintaining their own test runner script under
`scripts/`.** Currently only Windows has one.

## File layout

```
tests/
├── common/mod.rs          — shared helpers (SandboxGuard, config, drain_until, …)
├── lifecycle.rs           — start/stop, shell_id before/after lifecycle
├── shell.rs               — stdout echo, env leak, multi-command
├── fuse_mount.rs          — host↔guest FUSE visibility, dynamic add/remove
├── network.rs             — NetworkPolicy Blocked/AllowAll, IPv4/IPv6, diagnostics
├── netstack_stress.rs     — curl loops, PTY full-output, HTTPS throughput
├── concurrency.rs         — status RPC under load, bash background jobs
├── signal.rs              — SIGINT delivery via interrupt_shell
├── multi_session.rs       — concurrent sessions, distinct VM isolation
├── multi_shell.rs         — spawn/close/signal/list_shells lifecycle
├── pty.rs                 — PTY size, resize, Ctrl-C, ANSI escape passthrough
├── shared_session.rs      — SharedBackend registry: same/different session_id
├── rootfs.rs              — packaged rootfs tool versions (node, python)
├── macos_nfs.rs           — macOS-only NFS dynamic mount write-back
└── README.md              — this file
```

Each `.rs` file compiles as a separate integration test crate. Run all of
them at once with `cargo test` (no `--test` flag needed).

## Test inventory

35 tests (+ platform-specific), all currently green:

| # | File | Test | What it asserts |
|---|------|------|-----------------|
| 1 | lifecycle | `lifecycle_start_and_stop` | `configure → start_vm → stop_vm` round-trip clean |
| 2 | lifecycle | `shell_id_before_start` | `shell_id()` errors before `start_vm` |
| 3 | lifecycle | `shell_id_after_stop_is_error` | `shell_id()` errors after `stop_vm` |
| 4 | shell | `shell_env_does_not_leak_init_control_vars` | init control vars not visible in shell env |
| 5 | shell | `shell_stdout_echo` | `write_stdin("echo X\n")` → guest emits `X` on event stream |
| 6 | shell | `shell_runs_multiple_commands` | `pwd` / `uname -a` / `id` output captured |
| 7 | fuse_mount | `fuse_host_file_visible_in_guest` | Host sentinel file visible via `cat` in guest |
| 8 | fuse_mount | `fuse_dynamic_add_remove` | `add_mount` exposes content; `remove_mount` retracts it |
| 9 | concurrency | `status_rpcs_during_blocking_shell` | `is_running()` returns under load (5 calls in <2 s) |
| 10 | concurrency | `concurrent_commands_in_single_shell` | `(sleep 2; echo A) & (sleep 5; echo B) & wait` finishes in ~5s |
| 11 | signal | `signal_shell_delivers_sigint` | `interrupt_shell` → `Event::Exit { signal: Some(2) }` |
| 12 | multi_session | `multi_session_concurrent` | Two parallel sessions, no cross-talk |
| 13 | multi_session | `distinct_session_ids_get_distinct_vms` | Different session_id → isolated VMs |
| 14 | multi_shell | `multi_shell_isolated_streams` | Two shells' stdout streams don't leak into each other |
| 15 | multi_shell | `multi_shell_independent_signals` | `signal_shell(A, SIGINT)` kills only A; B stays alive |
| 16 | multi_shell | `list_shells_tracks_lifecycle` | `list_shells()` tracks spawn/close correctly |
| 17 | pty | `pty_shell_reports_correct_size` | `stty size` reports configured rows/cols |
| 18 | pty | `pty_shell_resize_propagates` | `resize_shell` → `stty size` reflects new dimensions |
| 19 | pty | `pty_shell_ctrl_c_does_not_kill_shell` | Ctrl-C in PTY kills foreground job, not the shell |
| 20 | pty | `pty_shell_color_escape_codes_pass_through` | ANSI color escapes preserved byte-for-byte |
| 21 | shared_session | `shared_session_two_handles_see_same_shell` | Same session_id → shared boot shell |
| 22 | shared_session | `shared_session_writes_visible_via_other_handle` | Handle B's write visible on handle A's event stream |
| 23 | shared_session | `stop_from_one_handle_tears_down_for_others` | `stop_vm` on one handle → all handles see `not running` |
| 24 | shared_session | `empty_session_id_is_not_shared` | Empty session_id → untracked, isolated VMs |
| 25 | rootfs | `rootfs_node_version` | Packaged rootfs has Node 24.x |
| 26 | rootfs | `rootfs_python_version` | Packaged rootfs has Python 3.x |
| 27 | network | `network_blocked_only_loopback` | Blocked → 2 links (lo+tk0), egress denied |
| 28 | network | `network_allow_all_has_nic` | AllowAll → ≥2 links, egress to 1.1.1.1:53 succeeds |
| 29 | network | `network_allow_all_icmpv4_ping` | ICMPv4 ping `#[ignore]` |
| 30 | network | `network_allow_all_ipv6_tcp` | IPv6 TCP to 2606:4700:4700::1111:53 |
| 31 | network | `network_allow_all_icmpv6_ping` | ICMPv6 ping |
| 32 | network | `network_allow_all_tcp_recv_payload` | v4 HTTP GET → HTTP 200 + ≥500B body |
| 33 | network | `network_allow_all_tcp_recv_payload_ipv6` | v6 HTTP GET → HTTP status + ≥200B body |
| 34 | network | `network_allow_all_tcp_recv_payload_ipv6_repeat` | v6 HTTP ×5 sequential |
| 35 | network | `network_allow_all_dns_then_tcp_v6_repeat` | DNS+TCP v6 ×3 sequential |
| 36 | network | `network_allow_all_dns_then_tcp_v6_long_sequence` | DNS+TCP v6 ×10 with 1s pause |
| 37 | network | `network_allow_all_ipv6_diag` | IPv6 diagnostic `#[ignore]` |
| 38 | network | `network_allow_all_diag` | v4 diagnostic `#[ignore]` |
| 39 | netstack_stress | `network_allow_all_curl_v6_baidu_loop` | `curl -6` baidu ×10 |
| 40 | netstack_stress | `network_allow_all_curl_v6_baidu_pty_full_output` | PTY + `curl -6` baidu ×30 full output |
| 41 | netstack_stress | `netstack_https_throughput` | HTTPS throughput ×10 `#[ignore]` |
| 42 | macos_nfs | `nfs_dynamic_mount_writes_to_host` | macOS NFS guest→host write-back `#[cfg(target_os)]` |

## Windows

### Hard requirements

| Requirement | Why |
|---|---|
| **sudo** | HCS / HCN (Hyper-V Host Compute Service / Network) require SYSTEM-level access. The library connects to `\\.\pipe\tokimo-sandbox-svc` which is owned by the SYSTEM-level service. Use `sudo` to elevate. |
| **Hyper-V feature enabled** | `Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All` must report `Enabled`. |
| **PowerShell 7 (`pwsh.exe`)** | The wrapper script uses strict mode and fails on `cargo`'s stderr-on-success under Windows PowerShell 5.1 (`$ErrorActionPreference='Stop'` + `NativeCommandError`). PS 7 handles it correctly. Path: `C:\Program Files\PowerShell\7\pwsh.exe`. |
| **VM artifacts in `.vm/base/`** | `.vm/base/vmlinuz`, `.vm/base/initrd.img`, `.vm/base/rootfs.vhdx` must exist. Pull via `pwsh scripts/windows/fetch-vm.ps1`. |
| **`tokimo-sandbox-svc` running** | Either as an installed service (`tokimo-sandbox-svc.exe --install`) or in console mode (`tokimo-sandbox-svc.exe --console`). The runner script auto-launches console mode when needed. |
| **WAN NIC `Forwarding=Enabled`** | Required for `network_allow_all_has_nic`. HCN's NAT network only enables IP forwarding on its own `vEthernet (tokimo-sandbox-nat)` adapter; the host's WAN-facing physical NIC defaults to `Forwarding=Disabled`, which causes reverse-NAT'd return packets to be misrouted out the WAN instead of into the NAT vSwitch. The guest then never sees a SYN-ACK and `bash exec 3<>/dev/tcp/...` hangs past 5 s with probe text `NET_PROBE_DONE`. Fix (sudo, one-shot, no reboot): `Set-NetIPInterface -InterfaceAlias '<WAN-alias>' -Forwarding Enabled`. See [docs/network-allow-all-failure-investigation.md](../docs/network-allow-all-failure-investigation.md) for the full pktmon trace. |

### Run

```powershell
# From repo root, with sudo.
sudo pwsh scripts\test-integration.ps1
```

The script:

1. Checks that the current shell has admin rights via sudo (exits with code 87 if not).
2. Builds `tokimo-sandbox-svc.exe` and the integration test binaries.
3. Launches `tokimo-sandbox-svc.exe --console` (logs → `target/integration/svc.log`).
4. Runs `cargo test` (logs → `target/integration/test.log`).
5. Cleans up the service process.

From a normal shell (Claude Code, CI, etc.):

```powershell
sudo pwsh scripts\test-integration.ps1
```

### Correct end-to-end procedure (after editing source)

The integration suite spans **three** build artifacts; if any of them is
stale, tests run against old code and fail mysteriously. Always do these
in order from a normal shell, then run with sudo:

| Edited file path | Required rebuild step | Why |
|---|---|---|
| `src/lib.rs`, `src/api.rs`, `src/windows/**`, `src/svc_protocol.rs`, `src/shared_backend.rs`, `src/bin/tokimo-sandbox-svc/**`, `tests/**` | (none — `test-integration.ps1` rebuilds these) | The wrapper script invokes `cargo build` and `cargo test` which produce `target/debug/tokimo-sandbox-svc.exe` + the test binaries. |
| `src/bin/tokimo-sandbox-init/**`, `src/protocol/**`, `packaging/vm-base/init.sh` | **`pwsh scripts\windows\rebake-initrd.ps1 -InstallToVm`** | The init binary runs **inside the guest VM**, not on Windows. It must be cross-compiled to `x86_64-unknown-linux-musl` and packed into `.vm/base/initrd.img`. `cargo build` alone does not do this. |
| Anything else in `src/` (lib code shared by both sides) | Both of the above | The lib is linked into both `tokimo-sandbox-svc.exe` (host) and `tokimo-sandbox-init` (guest). |

#### Binary lock: `cargo build --tests` vs running service

`cargo build --tests` triggers a relink of **all** binaries that depend
on the library, including `tokimo-sandbox-svc.exe`. If the service is
already running, Windows holds an exclusive lock on the `.exe` and the
relink fails with `Access is denied (os error 5)`. The
`test-integration.ps1` script kills the service before building, but if
you run `cargo build` or `cargo test` manually while the service is up,
you will hit this.

**Safe manual workflow:**

```powershell
# 1. Kill service + leftover VMs (sudo).
Get-Process tokimo-sandbox-svc -ErrorAction SilentlyContinue | Stop-Process -Force
hcsdiag.exe list | Select-String 'tokimo-sess' | ForEach-Object {
    if ($_ -match '([0-9A-F-]{36})') { hcsdiag.exe kill $matches[1] }
}

# 2. Build everything (service is not running, so relink succeeds).
cargo build --tests

# 3. Launch service + run tests (-SkipBuild skips the redundant rebuild).
scripts\windows\test-integration.ps1 -SkipBuild
```

#### `tokimo-sandbox-fuse` in the initrd

The FUSE-over-vsock mount channel requires the `tokimo-sandbox-fuse`
binary to be present inside the guest VM at `/bin/tokimo-sandbox-fuse`.
The `rebake-initrd.ps1` script cross-compiles all three guest binaries
(`tokimo-sandbox-init`, `tokimo-tun-pump`, `tokimo-sandbox-fuse`) and
swaps them into the initrd via the underlying
`packaging/vm/scripts/rebake-initrd.sh`. If you see
`spawn tokimo-sandbox-fuse: No such file or directory` in test output,
the initrd is stale — re-run `rebake-initrd.ps1 -InstallToVm`.

#### Pre-test cleanup (always)

Leftover Hyper-V VMs from previous runs hold `.vm/base/initrd.img` open and
will block both the rebake step and the next test run. Each test
session leaks a VM if the service is killed without `stopVm`. After a
few rounds you can have dozens of orphan VMs consuming gigabytes of RAM.

**Check what's running** (sudo pwsh):

```powershell
hcsdiag.exe list            # shows all HCS compute systems
(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB  # free GB
```

**Kill all tokimo VMs** (sudo pwsh — `hcsdiag kill` takes the compute
system **name**, not the GUID):

```powershell
hcsdiag.exe list | Select-String 'tokimo-sess' | ForEach-Object {
    if ($_ -match '(tokimo-sess-\S+)') { hcsdiag.exe kill $Matches[1] }
}
Get-Process tokimo-sandbox-svc -ErrorAction SilentlyContinue | Stop-Process -Force
```

**Verify** (should show 0 tokimo VMs):

```powershell
hcsdiag.exe list | Select-String 'tokimo-sess'
```

#### Run order

1. **Edit source.**
2. **If you touched `src/bin/tokimo-sandbox-init/**`, `src/protocol/**`,
   or `packaging/vm-base/init.sh`:** rebake (sudo required to release
   `.vm/base/initrd.img` lock from leftover VMs).
   ```powershell
   # Kill leftover VMs first if Copy-Item fails with "cannot access".
   hcsdiag.exe list | Select-String 'tokimo-sess' | ForEach-Object {
       if ($_ -match '(tokimo-sess-\S+)') { hcsdiag.exe kill $Matches[1] }
   }
   Get-Process tokimo-sandbox-svc -ErrorAction SilentlyContinue | Stop-Process -Force
   pwsh scripts\windows\rebake-initrd.ps1 -InstallToVm
   ```
3. **Run the wrapper with sudo** (do NOT pass `-SkipBuild`; cargo test
   will trigger a relink that races with the running svc.exe if its
   binary on disk is older than the lib).
   ```powershell
   sudo pwsh scripts\windows\test-integration.ps1
   ```
4. **Read results** from `target/integration/test.log` (the wrapper's
   own console output is lost when its window closes; capture it with
   `-Command "Start-Transcript ...; & ...; Stop-Transcript"` if needed).

Direct invocation (skip the wrapper, e.g. when you already have the service
running and a sudo terminal):

```powershell
sudo cargo test -- --nocapture
```

To run a single test file:

```powershell
sudo cargo test --test network -- --nocapture
```

To run a single test:

```powershell
sudo cargo test --test network network_blocked_only_loopback -- --nocapture
```

**Important:** `cargo test` rebuilds the lib and relinks all dependent
binaries. If `tokimo-sandbox-svc.exe` is currently running, the relink
will fail with `Access is denied`. Kill the service first, or use
`-SkipBuild` with the wrapper script. See "Binary lock" section above.

### Debug artefacts

| Path | Content |
|---|---|
| `target/integration/test.log` | Last `cargo test` output (test results) |
| `target/integration/svc.log` | Last service console-mode stdout |
| `C:\tokimo-debug\last-vm-com2.log` | Last guest kernel kmsg (COM2) |
| `C:\tokimo-debug\last-vm-tunnel.log` | Last init-control tunnel byte log |

### Cross-platform portability of the test source

The files use only public API types. Caveats per backend:

- **`Mount`**: all three backends use FUSE — Linux via
  FUSE-over-socketpair, macOS and Windows via FUSE-over-vsock. The
  same `FuseHost` + `tokimo-sandbox-fuse` infrastructure is shared
  across platforms. All three backends honor the same
  `Mount { name, host_path, guest_path }` contract — tests are
  written against observable behavior, not a specific transport.
- **`NetworkPolicy::AllowAll`**: each backend chooses its own egress
  path (Windows HCN NAT, Linux shared host netns, macOS bridged NAT
  via vmnet). Network tests only assert capability — link enumeration
  plus outbound TCP to `1.1.1.1:53`.
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
PATH="$PWD/target/debug:$PATH" cargo test -- --test-threads=1
```

`--test-threads=1` is recommended (each test spawns its own bwrap +
init pair; the bwrap default user-namespace creation rate is
self-throttling under heavy parallelism).

To run a single test file:

```bash
PATH="$PWD/target/debug:$PATH" cargo test --test network -- --test-threads=1 --nocapture
```

To run a single test:

```bash
PATH="$PWD/target/debug:$PATH" cargo test --test network network_blocked_only_loopback -- --test-threads=1 --nocapture
```

### Backend implementation notes

The Linux backend lives in `src/linux/`. Cross-cutting decisions worth
knowing when porting tests or debugging:

- **Mount story.** All three backends use FUSE for mounts. Linux uses
  FUSE-over-socketpair (`AF_UNIX SOCK_STREAM` socketpair per mount;
  host end served by `FuseHost`, guest end passed to
  `tokimo-sandbox-fuse` via `--transport unix-fd`). macOS and Windows
  use FUSE-over-vsock. Init holds `CAP_SYS_ADMIN` in the
  user-namespace so `fusermount3` can call `mount(2)`.
- **`/sys` is policy-aware.**
  * `AllowAll` → host `/sys` is bind-mounted read-only (the netns is
    shared, so the host NIC list is the correct view).
  * `Blocked`  → bwrap creates an empty `/sys` and init mounts a
    fresh `sysfs` from inside the new netns. A bind mount cannot
    replace this: sysfs filtering of `/sys/class/net` is per-mount,
    not per-task. Init keys off `TOKIMO_SANDBOX_MOUNT_SYSFS=1` set
    by the host.
- **Network policy.**
  * `AllowAll` → `--unshare-net` + smoltcp userspace netstack via TAP
    + socketpair. Full network access through the netstack proxy.
    Egress test hits `1.1.1.1:53` via the smoltcp TCP proxy.
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
| **Apple Silicon (arm64) host** | The bundled prebuilt rootfs / kernel under `packaging/vm-base/tokimo-os-arm64/` is arm64-only. |
| **macOS 13+** | Apple Virtualization.framework's modern `VZVirtioFileSystemDevice` + virtio-vsock support. |
| **Code-signed binary with `packaging/macos/vz.entitlements`** | Without `com.apple.security.virtualization`, `start_vm()` fails with: *"The process doesn't have the com.apple.security.virtualization entitlement."* |
| **VM artifacts at `<repo>/.vm/base/`** | Build or download via `scripts/macos/build-vm-local.sh` or `scripts/linux/fetch-vm.sh`. |
| **No service / no admin** | Like Linux, the macOS backend is library-only — `Sandbox::connect()` is a no-op. The host process directly drives `arcbox-vz` → Virtualization.framework. |

### One-time setup

```sh
# 1. Build or download VM artifacts into .vm/base/
scripts/macos/build-vm-local.sh        # arm64 (default, needs Docker)
# or: scripts/linux/fetch-vm.sh        # download from CI releases

# 2. Wire up the codesign cargo runner in your local .cargo/config.toml
#    (gitignored). It ad-hoc-signs every test/example binary with
#    packaging/macos/vz.entitlements before exec.
cat > .cargo/config.toml <<'EOF'
[target.aarch64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"

[target.x86_64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"
EOF
```

See [`docs/macos-testing.md`](../docs/macos-testing.md) for full details.

### Run

```sh
cargo test -- --test-threads=1
```

`--test-threads=1` is required: the VZ dispatch queue does not tolerate
parallel `vm.start()` calls from a single process. The macOS backend
also takes a process-wide `BOOT_LOCK` mutex around `vm.build()` /
`vm.start()`, but the integration suite shares one host process, so
parallel test threads would still serialize on it and time out.

To run a single test file:

```sh
cargo test --test network -- --test-threads=1 --nocapture
```

To run a single test:

```sh
cargo test --test network network_blocked_only_loopback -- --test-threads=1 --nocapture
```

### Backend implementation notes

The macOS backend lives in `src/macos/`. Cross-cutting decisions worth
knowing when porting tests or debugging:

- **Mount story.** `Mount { host_path, guest_path }` is **not**
  implemented over FUSE-over-vsock. macOS uses FUSE-over-vsock:
  - `tag="work"` — read-only host workspace tree (the per-Sandbox
    `session_dir` lives under `~/.tokimo/sessions/...`).
  - `tag="tokimo_dyn"` — a per-session dynamic pool mounted at
    `/__tokimo_dyn` inside the guest. `add_mount` /
    `remove_mount` create/destroy bind mounts inside this pool
    via init RPCs, exposing the same `host_path → guest_path` contract
    as the Windows FUSE-over-vsock backend. The transport differs
    (virtio-fs vs FUSE), but fuse_mount tests pass because they target
    observable behavior.
- **Network policy.**
  * `AllowAll` → `VZNetworkDeviceConfiguration::nat()` (vmnet-backed).
    vmnet hands out a runtime-chosen subnet (typically
    `192.168.64.0/24`), which does **not** match the
    `192.168.127.0/24` that `init.sh` hard-codes for Hyper-V. After the
    init handshake, the backend therefore runs busybox `udhcpc` inside
    the guest (with an inline `/tmp/udhcpc.sh` lease-apply script) to
    pick up the actual lease + default route. Only then does the egress
    test to `1.1.1.1:53` succeed.
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

## Editing tests

Conventions used by the existing suite:

- **`SandboxGuard`**: every `start_vm()` call must be followed by
  `let _guard = SandboxGuard(sb.clone());`. The guard calls
  `stop_vm()` on drop, preventing VM leaks when a test panics. The
  explicit `stop_vm()` in the test body is still fine — it's
  idempotent. Without the guard, a panicked test leaves an orphan VM
  running, consuming ~4 GB RAM until manually killed via `hcsdiag`.
  See "Pre-test cleanup" above for how to kill orphans.

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
- Shared helpers live in `tests/common/mod.rs`. Each test file includes
  `mod common;` at the top. Add new helpers there rather than duplicating
  across files.
