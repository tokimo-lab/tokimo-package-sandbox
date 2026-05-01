# Phase 2 — Status snapshot

POC stage. Best architecture, no backward-compat. This note summarises what
landed in Phase 2 and what is deferred.

## API surface (post-Phase 2)

The library exposes a single command-style `Sandbox` handle. The legacy
exec/spawn/kill RPCs are gone — there is **one** persistent shell per
session, identified by `shell_id()`, and stdin/stdout/signals are bound to
that shell.

| Public method | Purpose |
|---|---|
| `Sandbox::connect()` | Open the named-pipe / Unix-socket transport |
| `configure(ConfigureParams)` | Stage VM config (rootfs, mem, cpu, plan9 shares, network) |
| `create_vm()` / `start_vm()` / `stop_vm()` | Lifecycle |
| `subscribe()` → `Receiver<Event>` | Stream stdout / stderr / exit |
| `shell_id()` → `JobId` | The single guest shell handle (PID 1's child) |
| `write_stdin(&JobId, &[u8])` | Append to the shell's stdin pipe |
| `signal_shell(i32)` / `interrupt_shell()` | New in Phase 2 — POSIX signal delivery |
| `add_plan9_share` / `remove_plan9_share` | Dynamic share management |
| `status()` | Live VM state snapshot |

## Wire protocol

`PROTOCOL_VERSION = 3`. New RPC method `signalShell` with `SignalShellParams { sig: i32 }`.
Service handler reads the active session's `shell_child_id`, then forwards
`Op::Signal { child_id, sig, to_pgrp: true }` to the guest init via the
existing transparent pipe tunnel (Linux SEQPACKET / vsock stream).

## Test coverage

| Layer | Count | Where |
|---|---|---|
| Library unit tests | 13 | `cargo test --lib` |
| `tokimo-sandbox-svc` unit tests | 34 | `cargo test --bin tokimo-sandbox-svc --lib` |
| Integration (Windows, requires admin + Hyper-V) | 13 | `scripts/test-integration.ps1` |

Integration suite (all green):

1. `lifecycle_start_and_stop`
2. `shell_id_before_start` (negative)
3. `shell_id_after_stop_is_error` (negative)
4. `shell_stdout_echo`
5. `shell_runs_multiple_commands`
6. `plan9_host_file_visible_in_guest`
7. `status_rpcs_during_blocking_shell`
8. `multi_session_concurrent`
9. `plan9_dynamic_add_remove`
10. `signal_shell_delivers_sigint` — verifies `Event::Exit { signal: Some(2) }`
11. `network_blocked_only_loopback` — guest sees only `lo` when `NetworkPolicy::Blocked`
12. `network_allow_all_has_nic` — `eth0` enumerated via `hv_netvsc`, `192.168.127.2/24` configured
13. `concurrent_commands_in_single_shell` — bash `& wait` parallelism, ~5s for sleep(2)+sleep(5)

## Architecture cleanup

`src/bin/tokimo-sandbox-svc/imp/vmconfig.rs`: removed all dead code
(`PORT_WORK`, `PORT_INIT_CONTROL`, `build`, `build_ex`, `build_session_v2`).
Only `build_session_v2_ex` remains, with 6 unit tests covering schema,
hvsock GUID format, port allocator distinctness, network endpoint
attachment, and zero-share validation.

`src/bin/tokimo-sandbox-svc/imp/hcs.rs`: removed unused
`PfnGetProps` / `HcsState` / `get_props` / `get_exit_code` / `get_runtime_id`
/ `poll_state`. The remaining surface is just create / start /
terminate / close.

## Known gaps

### Pipe-mode shell cannot survive SIGINT

The single per-session shell is spawned without a controlling TTY (pipes
only). Default SIGINT disposition therefore terminates bash. The wire path
is verified end-to-end (see `signal_shell_delivers_sigint`) but interactive
"break-current-line" semantics are out of scope until a PTY-mode shell is
plumbed through `tokimo-sandbox-init`.

### `NetworkPolicy::Blocked` is structurally enforced

When `Blocked`, the service skips HCN endpoint allocation entirely and the
HCS schema contains no `NetworkAdapters` block. The guest kernel therefore
has no way to see any non-loopback interface — confirmed by
`network_blocked_only_loopback`. No firewall / nftables shim is needed.
