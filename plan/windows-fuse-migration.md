# Windows: Replace Plan9 with FUSE-over-vsock

## Context

All user mounts (boot-time + dynamic) should go through FUSE-over-vsock. Rootfs stays as-is (VHDX on SCSI). This unifies the mount channel with macOS. Windows currently uses HCS Plan9 (9P) for all user mounts; this plan replaces it with the same FUSE-over-vsock mechanism macOS uses.

## Design: Host-side FUSE in the Windows Service

The macOS backend runs FuseHost in-process with tokio. The Windows service (`tokimo-sandbox-svc`) is entirely synchronous — uses `std::thread::spawn` for concurrency, no tokio runtime. The key challenge is hosting FuseHost (async) inside the service.

**Approach:** Add `tokio` as a dependency for the service binary. Spin up a dedicated `tokio::runtime::Runtime` per session for FuseHost. Accept HvSocket connections in a background thread (blocking accept loop), convert raw `SOCKET` handles to async streams, and feed them to `FuseHost::serve()` on the tokio runtime. This mirrors what macOS does in `spawn_fuse_accept_loop` (converting VZ vsock connections to tokio streams).

**HvSocket → tokio bridge:** HvSocket sockets are Winsock2 `SOCKET` handles that support standard `recv()`/`send()`. After `accept()`, convert `SOCKET` → `OwnedSocket` → spawn a blocking I/O thread per connection that bridges to `tokio::io::duplex()` (in-memory async stream pair). The FuseHost side gets a clean `AsyncRead + AsyncWrite` interface.

**WinInitClient additions:** Add `mount_fuse(name, vsock_port, target, read_only)` and `unmount_fuse(name)` methods — same pattern as the existing `add_mount`/`remove_mount` (synchronous Op send + Reply recv).

## Files to Modify

### 1. `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs`

- Add `alloc_fuse_port()` — allocates a vsock port for the FUSE listener (range: `0x5000_0000 .. 0x50FFFFFF`, high range like init_port to avoid collision with Plan9's low range and to encode nicely into HvSocket GUID).
- **Remove** `alloc_share_port()` and `alloc_plan9_port()` (dead code after Plan9 removal).
- **Remove** `V2Share` struct.
- In `build_session_v2_ex()`:
  - Remove the `shares` parameter.
  - Remove the entire `Plan9.Shares` section from the generated JSON.
  - Add `fuse_port` parameter. Register its HvSocket service GUID in the service table (alongside init_port and netstack_port).
  - Add `tokimo.fuse_port=<port>` to the kernel cmdline so the guest init knows where to connect.
- **Remove** `plan9_modify_request()` entirely.

### 2. `src/bin/tokimo-sandbox-svc/imp/mod.rs`

#### SessionState changes
- Remove `active_shares: HashMap<String, ActiveShare>`.
- Remove `ActiveShare` struct.
- Add:
  ```rust
  fuse_host: Option<Arc<FuseHost>>,
  fuse_port: u32,
  fuse_mount_names: HashMap<String, u32>,  // name -> mount_id
  boot_mount_names: HashSet<String>,       // names from ConfigureParams.mounts
  fuse_rt: Option<tokio::runtime::Runtime>, // dedicated tokio runtime for FuseHost
  ```

#### handle_start_vm() changes
- Remove Plan9 share port allocation (`alloc_share_port`).
- Remove `V2Share` construction.
- Call `build_session_v2_ex()` **without** shares (pass `fuse_port` instead).
- After HCS starts and init Hello completes:
  - Create `FuseHost::new()`.
  - Start a dedicated tokio runtime (`fuse_rt`).
  - Spawn an HvSocket accept loop on `fuse_port` (in a background thread). For each accepted connection:
    - Extract raw socket HANDLE from HvSocket.
    - Convert to `OwnedFd` / `std::os::windows::io::RawSocket`.
    - Create a `tokio::net::UnixStream` (or custom AsyncRead/AsyncWrite wrapper).
    - Spawn `fuse_host.serve(stream)` on the tokio runtime.
  - For each mount in `ConfigureParams.mounts`:
    - Create `LocalDirVfs::arc(share.host_path)`.
    - `fuse_host.register_mount(name, backend, read_only)` → `mount_id`.
    - `init.mount_fuse(name, fuse_port, guest_path, read_only)` — sends `Op::MountFuse` to guest.
    - Record in `fuse_mount_names` and `boot_mount_names`.
- Remove `active_shares` population.

#### handle_add_mount() changes
- Remove `alloc_plan9_port()` call.
- Remove `plan9_modify_request("Add")` + `api.modify_compute_system()` call.
- Instead:
  - `fuse_host.register_mount(name, LocalDirVfs::arc(host_path), read_only)` → `mount_id`.
  - `init.mount_fuse(name, fuse_port, guest_path, read_only)`.
  - On failure: `fuse_host.remove_mount(mount_id)` (rollback).
  - Record in `fuse_mount_names`.

#### handle_remove_mount() changes
- Remove `plan9_modify_request("Remove")` + `api.modify_compute_system()` call.
- Instead:
  - Look up `mount_id` from `fuse_mount_names`.
  - `init.unmount_fuse(name)` — guest does umount + SIGTERM fuse child.
  - `fuse_host.remove_mount(mount_id)`.
  - Remove from `fuse_mount_names`.

#### teardown_session() changes
- Drop `fuse_host` (causes in-flight serve tasks to see EOF).
- Shutdown `fuse_rt`.
- Clear `fuse_mount_names` and `boot_mount_names`.

#### Dispatch table
- No change to method names (`addMount`, `removeMount` stay the same). The internal implementation changes from Plan9 to FUSE.

### 3. `src/bin/tokimo-sandbox-svc/imp/hvsock.rs`

- Add `accept_hvsock_on_port(port) -> SOCKET` — binds an HvSocket listener on the given port and accepts one connection (blocking). Used by the FUSE accept loop thread.
- Add a helper to convert the accepted `SOCKET` to an async stream for FuseHost. HvSocket sockets are Winsock2 handles — use `OwnedSocket` + a blocking I/O thread per connection bridged via `tokio::io::duplex()`.

### 4. `src/windows/init_client.rs`

- **Add** `mount_fuse(&self, name: &str, vsock_port: u32, target: &str, read_only: bool) -> Result<()>` — sends `Op::MountFuse { id, name, vsock_port, target, read_only }` and waits for `Reply::Ack`. Same pattern as the macOS `vsock_init_client.rs:mount_fuse`.
- **Add** `unmount_fuse(&self, name: &str) -> Result<()>` — sends `Op::UnmountFuse { id, name }` and waits for `Reply::Ack`.
- `send_mount_manifest()` — **remove** (no more Plan9 manifest).
- `add_mount()` — **remove** (replaced by `mount_fuse`).
- `remove_mount()` — **remove** (replaced by `unmount_fuse`).

### 5. `src/svc_protocol.rs`

- No changes to `addMount`/`removeMount` method names — the library side (`src/windows/sandbox.rs`) stays unchanged.
- `AddMountParams` / `RemoveMountParams` stay the same.
- Remove any Plan9-specific types if they exist here (they don't — `Mount` is shared).

### 6. `src/protocol/types.rs`

- `Op::MountManifest`, `Op::AddMount`, `Op::RemoveMount` — mark as deprecated or remove. These are Plan9-only. The init already handles `Op::MountFuse` / `Op::UnmountFuse`.
- `MountEntry` struct — remove (only used by Plan9 ops).
- `Reply::MountManifest` — remove.
- Update `default_features()`: remove `"mount_manifest"`, keep `"fuse_mount"`.

### 7. `src/bin/tokimo-sandbox-init/server.rs`

- Remove `mount_one()` (the 9p mount function).
- Remove `handle_mount_manifest()`.
- Remove `handle_add_mount()` / `handle_remove_mount()` (Plan9 ops).
- Remove `MountedShare` struct and `mount_fds` field from `State`.
- `handle_mount_fuse()` and `handle_unmount_fuse()` stay as-is (already implemented).

### 8. `src/bin/tokimo-sandbox-init/main.rs`

- Remove any references to `mount_manifest` feature.
- The vsock kernel module loading and VM boot mounts stay unchanged.

### 9. `packaging/vm-base/init.sh`

- Remove the 9p kernel module loading section (lines 87-91: `netfs`, `9pnet`, `9pnet_fd`, `9p`). FUSE is already loaded (line 113).
- Remove the Plan9 fallback rootfs path (lines 160-178) — dead code in v2 architecture, and now formally removed.
- Remove `WORK_PORT` / `ROOTSHARE_PORT` parsing from cmdline (lines 26-27, 36-37). These cmdline keys are no longer emitted.
- Update header comments (lines 6-8): replace "TWO Plan9-over-vsock shares" with "FUSE-over-vsock for user mounts".
- Keep the SCSI rootfs path (lines 140-158) as-is.
- Keep the virtiofs macOS path (lines 123-129) as-is.
- Keep the vsock9p binary in the initrd for now (removal requires a VM image rebuild). It becomes dead code.

### 10. `tests/sandbox_integration.rs`

- Rename `plan9_host_file_visible_in_guest` → `fuse_host_file_visible_in_guest` (line 185).
- Rename `plan9_dynamic_add_remove` → `fuse_dynamic_add_remove` (line 284).
- Update comments referencing "Plan9" (lines 181, 280, 983).
- The test logic itself doesn't change — the `Sandbox` API is the same.

### 11. `src/api.rs`

- Update `Mount` doc comment: change "Plan9 on Windows" to "FUSE-over-vsock on Windows".

### 12. `src/linux/sandbox.rs`

- Update comment on line ~299 that says "runtime-added Plan9 shares" — change to "runtime-added dynamic shares".

### 13. `CLAUDE.md` and `docs/windows-architecture.md`

- Update architecture diagrams: Windows now uses FUSE-over-vsock for user mounts, not Plan9.
- Update the Windows architecture section.

## HvSocket → AsyncRead/AsyncWrite Bridge (Key Technical Detail)

HvSocket on Windows uses `AF_HYPERV` Winsock2 sockets. After `accept()`, the resulting `SOCKET` handle supports standard `recv()`/`send()`. On Windows, tokio's reactor uses IOCP which works with any Winsock socket. The conversion path:

```
HvSocket accept → SOCKET → std::os::windows::io::OwnedSocket → tokio conversion
```

However, `tokio::net::TcpStream::from_std()` expects a `TcpStream`, not a generic socket. Instead, we can:
1. Use `socket2::Socket` to wrap the SOCKET.
2. Use `tokio::io::AsyncRead`/`AsyncWrite` via a custom wrapper that uses `tokio::task::spawn_blocking` for I/O ops.
3. Or: since FuseHost's `serve()` takes `impl AsyncRead + AsyncWrite`, create a thin `HvSocketAsync` wrapper that owns the raw SOCKET and implements the traits via blocking I/O in spawn_blocking.

The simplest correct approach: a dedicated thread per connection that does blocking read/write, bridged to tokio via `tokio::io::duplex()` (a pair of in-memory async streams). This avoids raw IOCP integration.

## Cargo.toml Changes

Add `tokio` as a dependency for the service binary (or the shared library, depending on how the feature flags are structured). The service needs:
- `tokio::runtime::Runtime` — for the FuseHost tokio runtime.
- `tokio::io::duplex` — for bridging HvSocket blocking I/O to async streams.
- `tokio::sync::mpsc` — optional, for the bridge.

Minimal features: `rt-multi-thread`, `io-util`, `sync`.

## What Stays Unchanged

- **Rootfs**: VHDX on SCSI (HCS VirtualDisk). No change.
- **Library side**: `src/windows/sandbox.rs` — still sends `addMount`/`removeMount` JSON-RPC. No change.
- **Named pipe protocol**: `src/svc_protocol.rs` — method names and param types stay the same.
- **Init control channel**: HvSocket for init_port stays the same.
- **Netstack**: smoltcp over vsock stays the same.
- **Linux backend**: No change (bwrap bind mounts).
- **macOS backend**: No change (already FUSE-over-vsock).

## Verification

1. `cargo build` — ensure everything compiles.
2. `cargo test --lib` — unit tests pass.
3. `cargo test --bin tokimo-sandbox-svc --lib` — service unit tests pass.
4. Manual test: `cargo run --bin tokimo-sandbox-svc -- --console`, create a sandbox with mounts, verify FUSE mounts appear in guest via `mount | grep fuse`.
5. Dynamic mount test: call `add_mount` at runtime, verify the new mount appears.
6. Dynamic unmount test: call `remove_mount`, verify it's gone.
