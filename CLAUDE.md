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

The library (`src/windows/`) connects to the SYSTEM service over `\\.\pipe\tokimo-sandbox-svc` using a JSON length-prefixed wire protocol (`src/windows/protocol.rs`). The service (`src/bin/tokimo-sandbox-svc/`) boots a Linux kernel+initrd (optionally with a VHDX rootfs) via HCS Schema 2.0, mounts the workspace over Plan9, runs the command inside the VM, and returns stdout/stderr/exit code.

The recommended deployment path is MSIX (`packaging/windows/`, `scripts/build-msix.ps1`), which registers the service with SCM via `desktop6:Service`. Legacy `--install` / `--console` flags exist for local development.

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
| `src/windows/client.rs` | Named-pipe client: `WaitNamedPipeW` → `CreateFileW` → send request → read response |
| `src/windows/protocol.rs` | Wire protocol types: `SvcRequest`, `SvcResponse`, length-prefixed framing |
| `src/windows/safe_path.rs` | TOCTOU-safe `canonicalize_safe`: rejects symlinks/junctions/hardlinks via `GetFileInformationByHandle` |
| `src/bin/tokimo-sandbox-svc/imp/mod.rs` | Service main: SCM lifecycle, pipe server loop, caller verification, `ExecVm` handler |
| `src/bin/tokimo-sandbox-svc/imp/hcs.rs` | HCS API wrapper: loads `ComputeCore.dll`, exposes `create/start/terminate/close/poll` |
| `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs` | HCS Schema 2.0 JSON config builder |
| `src/host/` | Cross-platform helpers (stdio plumbing, PTY, net observer) |
| `src/linux/` | Linux backend: bwrap + seccomp + init client |
| `src/macos/` | macOS backend: VZ virtual machine + vsock comms |
| `packaging/windows/AppxManifest.xml` | MSIX manifest declaring `desktop6:Service` |
| `scripts/build-msix.ps1` | MSIX build script (optional Authenticode signing) |

## Build & test

```powershell
# Build everything
cargo build

# Windows service (requires admin for --console mode)
cargo run --bin tokimo-sandbox-svc -- --console

# Tests
cargo test --lib
cargo test --bin tokimo-sandbox-svc --lib

# Package MSIX
pwsh ./scripts/build-msix.ps1
```

## Environment variables

| Variable | Purpose |
|---|---|
| `SAFEBOX_DISABLE=1` | Bypass sandbox entirely, run natively (debug escape hatch) |
| `TOKIMO_KERNEL` | Path to Linux kernel image (`vmlinuz`) |
| `TOKIMO_INITRD` | Path to initrd |
| `TOKIMO_ROOTFS_VHDX` | Path to rootfs VHDX (preferred) |
| `TOKIMO_ROOTFS` | Path to extracted rootfs directory (legacy Plan9 mode) |
| `TOKIMO_MEMORY` | VM memory in MB (default: 512) |
| `TOKIMO_CPUS` | VM vCPU count (default: 2) |
| `TOKIMO_VERIFY_CALLER=1` | Enforce Authenticode verification of pipe clients |
