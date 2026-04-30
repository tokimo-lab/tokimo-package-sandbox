# tokimo-package-sandbox

Cross-platform native sandbox for running arbitrary commands in isolated environments.

- **Linux**: bubblewrap (`bwrap`) + seccomp-bpf with optional eBPF L4 observer
- **macOS**: Apple Seatbelt (VZVirtualMachine / `arcbox-vz`)
- **Windows**: Hyper-V Host Compute Service (HCS) via a client-service architecture

## Architecture (Windows)

```
host process (library)  ──named pipe──▶  tokimo-sandbox-svc.exe (LocalSystem)
                                                │
                                                └── ComputeCore.dll (HCS API) ──▶ Hyper-V micro-VM
```

The library (`src/windows/`) connects to the SYSTEM service over `\\.\pipe\tokimo-sandbox-svc` using a JSON length-prefixed wire protocol (`src/windows/protocol.rs`). The service (`src/bin/tokimo-sandbox-svc/`) boots a Linux kernel+initrd (with a per-session VHDX clone for rootfs isolation) via HCS Schema 2.x, mounts the workspace over Plan9/vsock, and bridges the init control protocol over AF_HYPERV/HvSocket back to the library.

Two deployment modes:
- **MSIX** (`packaging/windows/`, `scripts/build-msix.ps1`): recommended for production — registers service name `TokimoSandboxSvc` via `desktop6:Service`.
- **CLI install** (`--install` / `--uninstall`): registers service name `tokimo-sandbox-svc` (lowercase-kebab) — for development. The two names are intentionally different so both can coexist on the same machine.
- **Console mode** (`--console`): foreground dev mode, no SCM registration needed.

## Windows APIs — all through the `windows` crate (verified)

**No hand-written FFI, no manual `extern "system"` blocks.** Every Win32 call goes through the `windows = "0.62"` crate. The only exception is `ComputeCore.dll` (HCS API), loaded dynamically via the `windows` crate's own `LoadLibraryW` + `GetProcAddress`.

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

### `src/windows/safe_path.rs` (TOCTOU-safe canonicalization)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `CloseHandle`, `GENERIC_READ`, `HANDLE` |
| `Win32_Storage_FileSystem` | `BY_HANDLE_FILE_INFORMATION`, `CreateFileW`, `FILE_ATTRIBUTE_REPARSE_POINT`, `FILE_FLAG_BACKUP_SEMANTICS`, `FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_SHARE_DELETE`, `FILE_SHARE_READ`, `FILE_SHARE_WRITE`, `GetFileInformationByHandle`, `OPEN_EXISTING` |
| `windows::core` | `HSTRING` |

### `src/bin/tokimo-sandbox-svc/imp/mod.rs` (service main)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `CloseHandle`, `GetLastError`, `HANDLE`, `HLOCAL`, `HWND`, `INVALID_HANDLE_VALUE`, `LocalFree` |
| `Win32_Security` | `SECURITY_ATTRIBUTES`, `PSECURITY_DESCRIPTOR` |
| `Win32_Security_Authorization` | `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `SDDL_REVISION_1` |
| `Win32_Security_WinTrust` | `WinVerifyTrust`, `WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WINTRUST_DATA`, `WINTRUST_DATA_0`, `WINTRUST_DATA_PROVIDER_FLAGS`, `WINTRUST_DATA_REVOCATION_CHECKS`, `WINTRUST_DATA_STATE_ACTION`, `WINTRUST_DATA_UICONTEXT`, `WINTRUST_FILE_INFO`, `WTD_CHOICE_FILE`, `WTD_UI_NONE` |
| `Win32_Storage_FileSystem` | `FlushFileBuffers`, `PIPE_ACCESS_DUPLEX`, `ReadFile`, `WriteFile` |
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

### `windows-service` crate (SCM integration)

From `windows-service = "0.8"` (only used in `imp/mod.rs`):

- `windows_service::service_dispatcher::start`
- `windows_service::define_windows_service!`
- `windows_service::service::{ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType}`
- `windows_service::service_control_handler::{self, ServiceControlHandlerResult}`
- `windows_service::service_manager::{ServiceManager, ServiceManagerAccess}`

### Cargo features declared but **NOT used** in source

These three are in `Cargo.toml` `[target.'cfg(target_os = "windows")'.dependencies]` but have no corresponding `use` in the codebase:

- `Win32_Security_Cryptography`
- `Win32_System_IO`
- `Win32_System_Memory`

## Key source layout

| Path | Purpose |
|---|---|
| `src/lib.rs` | Public API: `run()`, `SandboxConfig`, `NetworkPolicy`, `ExecutionResult` |
| `src/windows/mod.rs` | Windows backend entry point (library side): path discovery, network policy translation |
| `src/windows/session.rs` | `Session::open()`: path discovery → named-pipe OpenSession → `WinInitClient::new` → `hello()` → `open_shell()` |
| `src/windows/client.rs` | Named-pipe client: `WaitNamedPipeW` → `CreateFileW` (FILE_FLAG_OVERLAPPED) → send OpenSession request → read SessionOpened response |
| `src/windows/ov_pipe.rs` | **Critical**: OVERLAPPED Read/Write wrapper. Windows sync pipes serialize ReadFile+WriteFile on the same instance even across threads; OVERLAPPED mode is required for concurrent I/O |
| `src/windows/init_client.rs` | Runs the init control protocol (Hello/Spawn/Exec/Kill…) over the transparent pipe tunnel; reader thread + Mutex writer |
| `src/windows/protocol.rs` | Wire protocol types: `SvcRequest`, `SvcResponse`, length-prefixed framing |
| `src/windows/safe_path.rs` | TOCTOU-safe `canonicalize_safe`: rejects symlinks/junctions/hardlinks via `GetFileInformationByHandle` |
| `src/bin/tokimo-sandbox-svc/imp/mod.rs` | Service main: SCM lifecycle, pipe server loop, caller verification, per-session session handler |
| `src/bin/tokimo-sandbox-svc/imp/hcs.rs` | HCS API wrapper: loads `ComputeCore.dll`, exposes `create/start/terminate/close/poll` |
| `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs` | HCS Schema 2.x JSON config builder; `alloc_session_init_port()` for per-session hvsock GUIDs |
| `src/bin/tokimo-sandbox-svc/imp/hvsock.rs` | AF_HYPERV listener: `HV_GUID_WILDCARD` VmId (required by Hyper-V parent-partition rules) + per-session `ServiceId` |
| `src/host/` | Cross-platform helpers (stdio plumbing, PTY, net observer) |
| `src/linux/` | Linux backend: bwrap + seccomp + init client |
| `src/macos/` | macOS backend: VZ virtual machine + vsock comms |
| `packaging/windows/AppxManifest.xml` | MSIX manifest declaring `desktop6:Service` |
| `scripts/build-msix.ps1` | MSIX build script (optional Authenticode signing) |

## Build & test

```powershell
# Build everything
cargo build

# Console mode (dev, admin required — runs in foreground, no SCM)
cargo run --bin tokimo-sandbox-svc -- --console

# Install as SCM service (admin, registers as "tokimo-sandbox-svc")
.\target\debug\tokimo-sandbox-svc.exe --install
# Uninstall
.\target\debug\tokimo-sandbox-svc.exe --uninstall

# Tests (concurrent — 14 Windows session integration tests)
cargo test --test session -- --test-threads=4
# Or sequential (slower but no concurrency needed)
cargo test --test session -- --test-threads=1

# Unit tests only
cargo test --lib
cargo test --bin tokimo-sandbox-svc --lib

# Package MSIX
pwsh ./scripts/build-msix.ps1
```

## Environment variables

| Variable | Purpose |
|---|---|
| `SAFEBOX_DISABLE=1` | Bypass sandbox entirely, run natively (debug escape hatch) |
| `TOKIMO_VERIFY_CALLER=1` | Enforce Authenticode verification of pipe clients |

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
