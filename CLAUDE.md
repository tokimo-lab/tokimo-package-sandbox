# tokimo-package-sandbox

Cross-platform native sandbox for running arbitrary commands in isolated environments.

- **Linux**: bubblewrap (`bwrap`) + seccomp-bpf with optional eBPF L4 observer
- **macOS**: Apple Virtualization.framework (via `arcbox-vz`) → Linux micro-VM, virtio-fs work share, virtio-vsock control plane
- **Windows**: Hyper-V Host Compute Service (HCS) via a client-service architecture

## Public API

A single [`Sandbox`](src/api.rs) handle exposes a command-style RPC interface (17 methods). Backed by a per-platform [`SandboxBackend`](src/backend.rs) trait implementation:

```rust
use tokimo_package_sandbox::{Sandbox, ConfigureParams, ExecOpts};

let sb = Sandbox::connect().unwrap();
sb.configure(ConfigureParams {
    user_data_name: "demo".into(),
    memory_mb: 4096,
    cpu_count: 4,
    ..Default::default()
}).unwrap();
sb.create_vm().unwrap();   // Windows: HCS compute system; Linux/macOS: no-op
sb.start_vm().unwrap();
let r = sb.exec(&["uname", "-a"], ExecOpts::default()).unwrap();
println!("{}", r.stdout_str());
sb.stop_vm().unwrap();
```

Key types exported from `src/lib.rs`: `Sandbox`, `SandboxBackend`, `ConfigureParams`, `ExecOpts`, `ExecResult`, `JobId`, `Event`, `NetworkPolicy`, `Plan9Share`, `Error`, `Result`.

## Architecture (Windows)

```
Sandbox client (library)  ──named pipe──▶  tokimo-sandbox-svc.exe (LocalSystem)
                                                │
                                                ├─ ComputeCore.dll (HCS API) ──▶ Hyper-V micro-VM
                                                └─ smoltcp userspace netstack ──▶ NAT (AllowAll)
```

The library (`src/windows/`) connects to the SYSTEM service over `\\.\pipe\tokimo-sandbox-svc` using JSON-RPC over length-prefixed frames (`src/svc_protocol.rs`). The service (`src/bin/tokimo-sandbox-svc/`) boots a Linux kernel+initrd (with a per-session VHDX clone for rootfs isolation) via HCS Schema 2.x, runs a userspace netstack (smoltcp) for NAT, mounts the workspace over Plan9/vsock, and bridges the init control protocol over AF_HYPERV/HvSocket back to the library.

Guest-side: `tokimo-sandbox-init` (`src/bin/tokimo-sandbox-init/`) runs as PID 1 inside the sandbox container. It supports two transports:
- **Unix SEQPACKET** — for Linux bwrap backend
- **VSOCK stream** — for macOS VZ and Windows Hyper-V backends

Wire protocol: `src/protocol/` (shared host ↔ init), `src/svc_protocol.rs` (host ↔ Windows service).

## Architecture (Linux)

```
Sandbox client (library, in-process)
        │
        ├─ socketpair(AF_UNIX, SOCK_SEQPACKET)
        │       child end → bwrap (CLOEXEC cleared in pre_exec)
        │
        └─ exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts
                       [--unshare-net for Blocked]
                       --bind / staging
                       --cap-add CAP_SYS_ADMIN
                       -- /path/to/tokimo-sandbox-init bwrap
                              --control-fd=<n>
                              [--bringup-lo --mount-sysfs for Blocked]
                                         │
                                         └─ runs as PID 2 (bwrap is PID 1)
                                            speaks the same protocol as the
                                            VM-mode init binary
```

No service, no daemon, no admin: the Linux backend is library-only and
each `Sandbox` owns its own bwrap+init pair. Plan9 / virtio-fs are not
available outside a VM, so `Plan9Share` is implemented via `--bind`
(static) and runtime `AddMountFd` ops (dynamic add/remove). API and
observable behavior match the Windows backend; the mount mechanism
differs.

`/sys` handling is policy-aware:
- **AllowAll** → bind-mount host `/sys` (shared netns, host NIC view).
- **Blocked**  → empty `/sys` mount point + init mounts a fresh `sysfs`
  inside the new netns. A bind mount cannot replace this because sysfs
  filtering of `/sys/class/net` is per-mount, not per-task.

## Architecture (macOS)

```
Sandbox client (library, in-process)
        │
        ├─ arcbox-vz → Apple Virtualization.framework (VZVirtualMachine)
        │       │
        │       ├─ VZLinuxBootLoader(vmlinuz, initrd.img)
        │       ├─ VZVirtioFileSystemDevice  tag="work"      ← rootfs (read-only host-shared)
        │       ├─ VZVirtioFileSystemDevice  tag="tokimo_dyn" ← dynamic Plan9Share pool
        │       ├─ VZVirtioSocketDevice (vsock CID/port 2222) ← init control plane
        │       ├─ VZNetworkDeviceConfiguration::nat()        ← AllowAll: vmnet NAT
        │       └─ VZSerialPortConfiguration                  ← guest console (debug)
        │
        └─ in-guest:
              tokimo-sandbox-init (PID 1) over virtio-vsock port 2222
                ├─ Hello / handshake
                ├─ mount the dynamic pool at /__tokimo_dyn
                ├─ AllowAll → run busybox udhcpc inside guest to apply
                │   the actual VZ NAT lease (vmnet picks ~192.168.64.x at
                │   runtime, NOT the Hyper-V 192.168.127.x baked into init.sh)
                ├─ OpenShell / Spawn / Exec
                └─ Plan9Share add/remove → bind dyn-pool subdirs at runtime
```

**Process-wide invariants:**
- `BOOT_LOCK` (a `Mutex`) serializes `vm.build()` + `vm.start()` — the VZ
  dispatch queue rejects parallel starts with "Start operation cancelled".
- Each `Sandbox` handle owns a unique `session_dir` under
  `~/.tokimo/sessions/<sanitized_name>-<session_id>-<pid>-<counter>` so
  concurrent sessions never collide.
- The host binary must be code-signed with `vz.entitlements` (the
  `com.apple.security.virtualization` entitlement). `cargo test` does this
  automatically via `scripts/codesign-and-run.sh` registered as a cargo
  runner; see `docs/macos-testing.md`.
- `tests/sandbox_integration.rs` (16/16 green) must run with
  `--test-threads=1` because the suite shares one host process and `BOOT_LOCK`
  enforces serial VM start anyway.

## Deployment modes (Windows)

- **MSIX** (`packaging/windows/`, `scripts/build-msix.ps1`): recommended for production — registers service name `TokimoSandboxSvc` via `desktop6:Service`.
- **CLI install** (`--install` / `--uninstall`): registers service name `tokimo-sandbox-svc` (lowercase-kebab) — for development. The two names are intentionally different so both can coexist on the same machine.
- **Console mode** (`--console`): foreground dev mode, no SCM registration needed.

## Windows APIs — all through the `windows` crate (verified)

**No hand-written FFI, no manual `extern "system"` blocks.** Every Win32 call goes through the `windows = "0.62"` crate. The exceptions are `ComputeCore.dll` (HCS API) and `computenetwork.dll` (HCN), loaded dynamically via the `windows` crate's own `LoadLibraryW` + `GetProcAddress`.

The verified API surface, grouped by file:

### `src/windows/client.rs` (library-side named pipe client)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `ERROR_PIPE_BUSY`, `GENERIC_READ`, `GENERIC_WRITE`, `GetLastError` |
| `Win32_Security` | `SECURITY_ATTRIBUTES` |
| `Win32_Storage_FileSystem` | `CreateFileW`, `FILE_FLAGS_AND_ATTRIBUTES`, `FILE_SHARE_NONE`, `OPEN_EXISTING` |
| `Win32_System_Pipes` | `WaitNamedPipeW` |
| `windows::core` | `HSTRING` |
| std | `std::os::windows::io::FromRawHandle` |

### `src/windows/ov_pipe.rs` (OVERLAPPED Read/Write wrapper)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `CloseHandle`, `DUPLICATE_SAME_ACCESS`, `DuplicateHandle`, `ERROR_BROKEN_PIPE`, `ERROR_HANDLE_EOF`, `ERROR_IO_PENDING`, `ERROR_PIPE_NOT_CONNECTED`, `GetLastError`, `HANDLE`, `WAIT_OBJECT_0` |
| `Win32_Storage_FileSystem` | `ReadFile`, `WriteFile` |
| `Win32_System_IO` | `GetOverlappedResult`, `OVERLAPPED` |
| `Win32_System_Threading` | `CreateEventW`, `GetCurrentProcess`, `INFINITE`, `WaitForSingleObject` |
| `windows::core` | `PCWSTR` |

### `src/windows/safe_path.rs` (TOCTOU-safe canonicalization)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `CloseHandle`, `GENERIC_READ`, `HANDLE` |
| `Win32_Storage_FileSystem` | `BY_HANDLE_FILE_INFORMATION`, `CreateFileW`, `FILE_ATTRIBUTE_REPARSE_POINT`, `FILE_FLAG_BACKUP_SEMANTICS`, `FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_SHARE_DELETE`, `FILE_SHARE_READ`, `FILE_SHARE_WRITE`, `GetFileInformationByHandle`, `OPEN_EXISTING` |
| `windows::core` | `HSTRING` |

### `src/bin/tokimo-sandbox-svc/imp/mod.rs` (service main)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `CloseHandle`, `ERROR_SUCCESS`, `GetLastError`, `HANDLE`, `HLOCAL`, `HWND`, `INVALID_HANDLE_VALUE`, `LocalFree` |
| `Win32_Security` | `SECURITY_ATTRIBUTES`, `PSECURITY_DESCRIPTOR` |
| `Win32_Security_Authorization` | `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `SDDL_REVISION_1` |
| `Win32_Security_WinTrust` | `WinVerifyTrust`, `WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WINTRUST_DATA`, `WINTRUST_DATA_0`, `WINTRUST_DATA_PROVIDER_FLAGS`, `WINTRUST_DATA_REVOCATION_CHECKS`, `WINTRUST_DATA_STATE_ACTION`, `WINTRUST_DATA_UICONTEXT`, `WINTRUST_FILE_INFO`, `WTD_CHOICE_FILE`, `WTD_UI_NONE` |
| `Win32_Storage_FileSystem` | `FlushFileBuffers`, `PIPE_ACCESS_DUPLEX`, `ReadFile`, `WriteFile` |
| `Win32_System_IO` | `OVERLAPPED` |
| `Win32_System_Pipes` | `ConnectNamedPipe`, `CreateNamedPipeW`, `DisconnectNamedPipe`, `GetNamedPipeClientProcessId`, `PIPE_READMODE_MESSAGE`, `PIPE_TYPE_MESSAGE`, `PIPE_UNLIMITED_INSTANCES`, `PIPE_WAIT` |
| `Win32_System_Registry` | `HKEY`, `HKEY_LOCAL_MACHINE`, `KEY_READ`, `REG_VALUE_TYPE`, `RegCloseKey`, `RegOpenKeyExW`, `RegQueryValueExW` |
| `Win32_System_Threading` | `OpenProcess`, `PROCESS_NAME_FORMAT`, `PROCESS_QUERY_LIMITED_INFORMATION`, `QueryFullProcessImageNameW` |
| `windows::core` | `HSTRING`, `PCWSTR`, `PWSTR` |
| std | `std::os::windows::ffi::EncodeWide`, `std::os::windows::ffi::OsStrExt` |

### `src/bin/tokimo-sandbox-svc/imp/hcs.rs` (ComputeCore.dll loader)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `FreeLibrary`, `HLOCAL`, `HMODULE`, `LocalFree` |
| `Win32_System_LibraryLoader` | `GetProcAddress`, `LoadLibraryW` |
| `windows::core` | `HSTRING`, `PCSTR` |

### `src/bin/tokimo-sandbox-svc/imp/hvsock.rs` (AF_HYPERV listener)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `DuplicateHandle`, `HANDLE` |
| `Win32_Networking_WinSock` | `AF_HYPERV`, `HV_GUID_WILDCARD`, `HV_GUID_ZERO`, `HVSOCKET_ADDRESS_INFO`, `HVSOCKET_CONNECT_TIMEOUT`, `HVSOCKET_CONNECTED_FLAG`, `HV_ADDRESS_FAMILY`, `WSADATA`, `WSAStartup`, `WSAGetLastError`, `bind`, `closesocket`, `listen`, `socket`, `WSAEACCES`, `WSAEADDRINUSE` |
| `Win32_System_Threading` | `GetCurrentProcess` |
| `windows::core` | `GUID` |

### `windows-service` crate (SCM integration)

From `windows-service = "0.8"` (only used in `imp/mod.rs`):

- `windows_service::service_dispatcher::start`
- `windows_service::define_windows_service!`
- `windows_service::service::{ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType}`
- `windows_service::service_control_handler::{self, ServiceControlHandlerResult}`
- `windows_service::service_manager::{ServiceManager, ServiceManagerAccess}`

### Cargo features declared but **NOT used** in source

These two are in `Cargo.toml` `[target.'cfg(target_os = "windows")'.dependencies]` but have no corresponding `use` in the codebase:

- `Win32_Security_Cryptography`
- `Win32_System_Memory`

## Key source layout

| Path | Purpose |
|---|---|
| `src/lib.rs` | Crate root: re-exports public API types, declares platform modules |
| `src/api.rs` | Public `Sandbox` handle (17 commands), `ConfigureParams`, `ExecOpts`, `ExecResult`, `Event`, `JobId`, `Plan9Share`, `NetworkPolicy` |
| `src/backend.rs` | `SandboxBackend` trait — per-platform implementation contract |
| `src/platform.rs` | `default_backend()` — dispatches to the OS-specific backend |
| `src/error.rs` | `Error` enum + `Result<T>` alias |
| `src/protocol/` | Host ↔ init wire protocol (shared across all backends) |
| `src/protocol/types.rs` | `Frame` envelope, `StdioMode`, op/event enums, version constants |
| `src/protocol/wire.rs` | Frame encode/decode, SEQPACKET + stream transport helpers |
| `src/svc_protocol.rs` | Host ↔ Windows service JSON-RPC: `Frame`, method names, typed param/result structs, `RootfsSpec` |
| `src/windows/mod.rs` | Windows backend module declarations |
| `src/windows/sandbox.rs` | `WindowsBackend: SandboxBackend` — forwards API calls as JSON-RPC over named pipe |
| `src/windows/client.rs` | Named-pipe client: `WaitNamedPipeW` → `CreateFileW` (FILE_FLAG_OVERLAPPED) → `Hello` handshake |
| `src/windows/ov_pipe.rs` | OVERLAPPED Read/Write wrapper for concurrent pipe I/O |
| `src/windows/init_client.rs` | Runs the init control protocol over the transparent pipe tunnel; reader thread + Mutex writer |
| `src/windows/safe_path.rs` | TOCTOU-safe `canonicalize_safe`: rejects symlinks/junctions/hardlinks |
| `src/linux/mod.rs` | Linux backend module declarations |
| `src/linux/sandbox.rs` | `LinuxBackend: SandboxBackend` — wraps bwrap in-process |
| `src/linux/init_client.rs` | Linux init client (Unix SEQPACKET transport) |
| `src/macos/mod.rs` | macOS backend module declarations |
| `src/macos/sandbox.rs` | `MacosBackend: SandboxBackend` — boots VZ virtual machine |
| `src/macos/vm.rs` | VZ VM lifecycle |
| `src/macos/vsock_init_client.rs` | macOS init client (VSOCK transport) |
| `src/bin/tokimo-sandbox-init/main.rs` | Guest PID 1 binary: accepts connections on SEQPACKET or VSOCK, manages child processes |
| `src/bin/tokimo-sandbox-init/server.rs` | Init's main request loop |
| `src/bin/tokimo-sandbox-init/child.rs` | Child process management (fork/exec, pipes, PTY) |
| `src/bin/tokimo-sandbox-init/pty.rs` | PTY allocation inside the guest |
| `src/bin/tokimo-sandbox-svc/main.rs` | Service entry point |
| `src/bin/tokimo-sandbox-svc/imp/mod.rs` | Service main: SCM lifecycle, pipe server loop, caller verification, per-session handler |
| `src/bin/tokimo-sandbox-svc/imp/hcs.rs` | HCS API wrapper: loads `ComputeCore.dll`, exposes create/start/terminate/close/poll |
| `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs` | HCS Schema 2.x JSON config builder; `alloc_session_init_port()` for per-session hvsock GUIDs |
| `src/bin/tokimo-sandbox-svc/imp/hvsock.rs` | AF_HYPERV listener with per-session ServiceId |
| `src/bin/tokimo-sandbox-svc/imp/vhdx_pool.rs` | Per-target rootfs VHDX leasing (ephemeral clone vs persistent lock) |
| `packaging/windows/AppxManifest.xml` | MSIX manifest declaring `desktop6:Service` |
| `scripts/build-msix.ps1` | MSIX build script (optional Authenticode signing) |

## Build & test

```powershell
# --- Windows ---

# Build everything
cargo build

# Console mode (dev, admin required — runs in foreground, no SCM)
cargo run --bin tokimo-sandbox-svc -- --console

# Install as SCM service (admin, registers as "tokimo-sandbox-svc")
.\target\debug\tokimo-sandbox-svc.exe --install
# Uninstall
.\target\debug\tokimo-sandbox-svc.exe --uninstall

# Tests (unit tests in #[cfg(test)] modules within the binary crate)
cargo test --lib
cargo test --bin tokimo-sandbox-svc --lib

# Package MSIX
pwsh ./scripts/build-msix.ps1
```

```bash
# --- Linux ---

# One-time
sudo apt install bubblewrap

# Build init binary so bwrap can exec it
cargo build --bin tokimo-sandbox-init

# Full integration suite (16 tests, ~8 s). --test-threads=1 keeps bwrap
# user-namespace creation rate sane and avoids cross-test PATH races.
PATH="$PWD/target/debug:$PATH" cargo test --test sandbox_integration -- --test-threads=1
```

```bash
# --- macOS (Apple Silicon) ---

# 1. Provide VM artifacts under <repo>/vm/ (symlinks are fine):
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/vmlinuz"    vm/vmlinuz
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/initrd.img" vm/initrd.img
ln -sf "$PWD/packaging/vm-image/tokimo-os-arm64/rootfs"     vm/rootfs

# 2. Register the codesign cargo runner once (in your gitignored
#    .cargo/config.toml; the runner ad-hoc-signs each test binary with
#    vz.entitlements before exec'ing):
#       [target.aarch64-apple-darwin]
#       runner = "scripts/codesign-and-run.sh"
#       [target.x86_64-apple-darwin]
#       runner = "scripts/codesign-and-run.sh"

# 3. Run. --test-threads=1 is required (the VZ dispatch queue cannot
#    handle parallel vm.start() calls from one process; BOOT_LOCK
#    enforces it inside the backend too).
cargo test --test sandbox_integration -- --test-threads=1
```

See `docs/macos-testing.md` for the full setup walkthrough.

## Environment variables

| Variable | Purpose |
|---|---|
| `SAFEBOX_DISABLE=1` | Bypass sandbox entirely, run natively (debug escape hatch) |
| `TOKIMO_VERIFY_CALLER=1` | Enforce Authenticode verification of pipe clients (Windows service) |
| `TOKIMO_SANDBOX_PRE_CHROOTED=1` | VM modes: skip init's mount/chroot setup because `init.sh` already did it |
| `TOKIMO_VM_DIR=<path>` | macOS / Windows: override VM artifact discovery (default walks up from cwd looking for `vm/`) |

Linux/bwrap configuration is passed via argv (subcommand `tokimo-sandbox-init bwrap --control-fd=<n> [--bringup-lo] [--mount-sysfs]`) rather than env vars, so nothing leaks into spawned children.

## Windows VM artifacts

Windows requires three files (`vmlinuz`, `initrd.img`, `rootfs.vhdx`) in `<repo>/vm/`. Built and published in-repo by `.github/workflows/vm-image.yml` under tags with prefix `vm-v*` (see `packaging/vm-image/README.md` for the build pipeline). Download via:

```powershell
pwsh scripts/fetch-vm.ps1                 # latest
pwsh scripts/fetch-vm.ps1 -Tag vm-v1.9.0  # specific
```

`src/windows/mod.rs::find_vm_dir()` walks up from the service exe / cwd looking for a `vm/` directory containing all three files. **No environment variables are consulted.**

## HvSocket concurrency — critical design note

Each session allocates a **unique vsock port** via `vmconfig::alloc_session_init_port()`, which encodes into a unique HvSocket service GUID (`{port:08X}-FACB-11E6-BD58-64006A7986D3`). This is required because:

1. Hyper-V requires `(VmId, ServiceId)` to be unique for host-side listeners.
2. The parent partition **must** use `HV_GUID_WILDCARD` as the listener VmId — binding a specific child's RuntimeId returns `WSAEACCES (10013)`.
3. Two wildcard listeners on the same ServiceId → `WSAEADDRINUSE (10048)`.

Therefore, the **only** way to run concurrent sessions is one `ServiceId` per session. Each service GUID is also registered in `HKLM\...\GuestCommunicationServices\<guid>` and the vsock port is passed to the guest kernel as `tokimo.init_port=<port>` on the cmdline.
