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
| `C:\tokimo-debug\last-hcs-session-config.json` | Last HCS schema 2.x config sent to ComputeCore.dll |
| `C:\tokimo-debug\last-hcn-network.json` | Last HCN NAT network create payload |
| `C:\tokimo-debug\last-hcn-endpoint.json` | Last HCN endpoint create payload |
| `C:\tokimo-debug\last-vm-com2.log` | Last guest kernel kmsg (COM2) |
| `C:\tokimo-debug\last-vm-tunnel.log` | Last init-control tunnel byte log |

### Test inventory

13 tests, all currently green (~36 s wall):

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
| 10 | `signal_shell_delivers_sigint` | `signal_shell(2)` produces `Event::Exit { signal: Some(2) }` |
| 11 | `network_blocked_only_loopback` | `NetworkPolicy::Blocked` → `/sys/class/net/` only `lo`; bash `/dev/tcp/1.1.1.1/53` times out |
| 12 | `network_allow_all_has_nic` | `NetworkPolicy::AllowAll` → `eth0` enumerated; bash `/dev/tcp/1.1.1.1/53` succeeds (real egress) |
| 13 | `concurrent_commands_in_single_shell` | `(sleep 2; echo A) & (sleep 5; echo B) & wait` finishes in <7 s wall (parallel, not sequential) and both stdout markers appear |

### Cross-platform portability of the test source

The file uses only public API types. Caveats per backend:

- **`Plan9Share`**: on Windows this maps to plan9-over-vsock (real shared
  filesystem). Linux (bwrap) and macOS (virtio-fs) have different mount
  semantics — when porting, audit `Plan9Share { name, host_path, guest_path }`
  and confirm `host_path` actually appears at `guest_path` for tests 6 and 9.
- **`NetworkPolicy::AllowAll`**: Windows uses HCN NAT (gateway 192.168.127.1).
  Linux/macOS will need a comparable egress path; the `1.1.1.1:53` TCP probe
  is generic.
- **`NetworkPolicy::Blocked`**: Windows simply omits the `NetworkAdapter`
  device from the HCS schema — kernel sees no NIC. Linux (bwrap with
  `--unshare-net`) and macOS will need their own enforcement.
- **`signal_shell` / `interrupt_shell`**: relies on init delivering SIGINT
  via `killpg`. The wire path is shared across backends — should port
  directly.

## Linux

_TODO: add `scripts/test-integration.sh` (bwrap + seccomp). When written, document here:_

- Required capabilities (`CAP_SYS_ADMIN` for user-namespace setup, etc.)
- Whether root is required
- How to invoke (`bash scripts/test-integration.sh`)
- Test inventory subset (some tests, e.g. plan9 dynamic add/remove, may need bind-mount equivalents)

## macOS

_TODO: add `scripts/test-integration-macos.sh` (VZ virtual machine). When written, document here:_

- VZ entitlement requirements (`com.apple.security.virtualization` — see `vz.entitlements`)
- Codesign step before running tests (`scripts/macos-codesign-examples.sh`)
- How to invoke
- Test inventory subset (network policy enforcement story differs — VZ doesn't have HCN; uses NAT through vmnet)

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
