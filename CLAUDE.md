# tokimo-package-sandbox

Cross-platform native sandbox for running arbitrary commands in isolated environments.

| Platform | Isolation engine | Root | Notes |
|---|---|---|---|
| **Linux (`ch`)** | Cloud Hypervisor micro-VM (KVM) + virtiofsd + smoltcp netstack | not required (kvm group) | Preferred when `/dev/kvm` + `/dev/vhost-vsock` + `cloud-hypervisor` binary available |
| **Linux (`bwrap`)** | bubblewrap (user namespaces) + smoltcp netstack | not required | Auto-fallback; ~50 ms start, no VM |
| **macOS** | Apple Virtualization.framework → Linux micro-VM + smoltcp netstack | not required | ~2 s cold |
| **Windows** | Hyper-V HCS → Linux micro-VM + smoltcp netstack via SYSTEM service | one-time install | ~600 ms |

All backends present the same `Sandbox` handle with identical semantics: configure → create → start → spawn shells → stop. A single init binary (`tokimo-sandbox-init`) runs as PID 1 (or PID 2 inside bwrap) in every sandbox, speaking the same wire protocol regardless of transport. Networking is unified: every backend uses the same smoltcp userspace netstack for `AllowAll`.

**Linux backend selection** (`SANDBOX_BACKEND` env):

| Value | Behavior |
|---|---|
| (unset) / `auto` | Probe `ch` first; fall back to `bwrap` if unavailable |
| `ch` | Force Cloud Hypervisor; fail if unavailable |
| `bwrap` | Force bubblewrap; fail if unavailable |
| `disabled` | Refuse to construct any backend |

`Sandbox::active_backend()` returns the concrete backend chosen at runtime.

## Public API

A single [`Sandbox`](src/api/mod.rs) handle exposes a command-style RPC interface (~30 methods). Backed by a per-platform [`SandboxBackend`](src/api/backend.rs) trait implementation:

```rust
use tokimo_package_sandbox::{Sandbox, ConfigureParams, NetworkPolicy};

let sb = Sandbox::connect().unwrap();
sb.configure(ConfigureParams {
    user_data_name: "demo".into(),
    memory_mb: 4096,
    cpu_count: 4,
    network: NetworkPolicy::AllowAll,
    ..Default::default()
}).unwrap();
sb.create_vm().unwrap();   // Windows: HCS compute system; Linux/macOS: no-op
sb.start_vm().unwrap();

let shell = sb.shell_id().unwrap();
sb.write_stdin(&shell, b"uname -a\n").unwrap();
// ... read events via sb.subscribe() ...

sb.stop_vm().unwrap();
```

Key types exported from `src/lib.rs`: `Sandbox`, `SandboxBackend`, `ConfigureParams`, `ShellOpts`, `Mount`, `NetworkPolicy`, `Event`, `JobId`, `HostExecCtx`, `HostExecAction`, `HostExecCallback`, `SessionSummary`, `SessionDetails`, `PortForwardSpec`, `Error`, `Result`, `SandboxBackendKind`, `ActiveBackend`, `FontDir`.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Your application                       │
│                                                             │
│   let sb = Sandbox::connect().unwrap();                     │
│   sb.configure(params).unwrap();                            │
│   sb.start_vm().unwrap();                                   │
│   let shell = sb.shell_id().unwrap();                       │
│   sb.write_stdin(&shell, b"uname -a\n").unwrap();           │
│   sb.stop_vm().unwrap();                                    │
└────────────────────────┬────────────────────────────────────┘
                         │  same API on all platforms
        ┌────────────────┼─────────────────────┬────────────────┐
        ▼                                      ▼                ▼
   LinuxBackend  ── Auto: ch → bwrap        MacosBackend   WindowsBackend
   (in-process; pick at connect())          (in-process)   (named-pipe RPC)
        │                                       │                │
        ├── ChBackend  ── cloud-hypervisor      ▼                ▼
        │   (KVM micro-VM, virtiofsd,      arcbox-vz →     tokimo-sandbox-svc
        │    hybrid-vsock UDS)             VZVirtualMachine    (SYSTEM service)
        │                                       │                │
        └── BwrapBackend                        │                │
            (bubblewrap user namespaces)        │                │
                  │                             │                ▼
                  │                             │          Hyper-V HCS
                  └────────────┬────────────────┘                │
                               ▼                                 ▼
                      tokimo-sandbox-init                 Linux micro-VM
                      (PID 1, shared binary)              (HvSocket transport)
                               │
                               ▼
                        Linux guest
```

### Linux — two backends, one API

The Linux platform layer probes for Cloud Hypervisor at `Sandbox::connect()` time and picks the strongest backend that works on the host. CH is preferred (real KVM isolation, full kernel boundary, identical posture to macOS/Windows); bwrap is the fallback (no VM, fastest startup, works without `/dev/kvm`).

Both backends share **everything except the isolation primitive**: the same `tokimo-sandbox-init` PID 1 binary, the same `FuseHost` + `tokimo-sandbox-fuse` FUSE infrastructure, the same smoltcp netstack, the same protocol frames. Only the transport wiring differs (SEQPACKET socketpairs vs. hybrid-vsock UDS sidecars).

### Linux — Cloud Hypervisor (`ch` backend)

```
Sandbox::start_vm()
  │
  ├─ probe_ch() ✅  (/dev/kvm + /dev/vhost-vsock + cloud-hypervisor + virtiofsd)
  │
  ├─ spawn cloud-hypervisor child:
  │      --kernel  vmlinuz                  ← packaged with crate version
  │      --initramfs initrd.img
  │      --cmdline "... tokimo.guest_listens=0 tokimo.init_port=2222 ..."
  │      --memory size=<MB>                 ← from ConfigureParams
  │      --cpus boot=<N>
  │      --vsock cid=3,socket=<vsock_uds>   ← hybrid-vsock; UDS sidecars per port
  │      --fs tag=<mount_name>,socket=<virtiofsd.sock>  ← repeated per share
  │      [--net tap=...]                    ← AllowAll only
  │
  ├─ spawn virtiofsd children (one per ConfigureParams.mount):
  │      --shared-dir <host_path>
  │      --socket-path <virtiofsd.sock>
  │      [--readonly] [--sandbox=none|chroot]
  │
  └─ host listeners on hybrid-vsock UDS sidecars (<vsock_uds>_<port>):
        port 2222 → init control plane
        port 4444 → smoltcp netstack RX/TX
        port 5555 → FuseHost (in-process FUSE-over-vsock)
```

- **No daemon, no service, no root.** Each `Sandbox` owns its own `cloud-hypervisor` + `virtiofsd` process group.
- **Same packaged kernel + initrd + rootfs** as macOS/Windows (`vm-kernel-*` + `vm-rootfs-*` tag artifacts).
- **vsock transport** uses CH's *hybrid-vsock* — host plays vsock by listening on per-port UDS files instead of `/dev/vhost-vsock`. All channels (init, netstack, FUSE, console) are guest-initiated.
- **File sharing** ConfigureParams mounts use `virtiofsd`. Runtime `add_mount` still uses FUSE-over-vsock through the same `FuseHost` as other backends.
- **Networking:** `AllowAll` uses the same smoltcp userspace netstack. `Blocked` omits the network device.
- **PTY:** Master fd stays in guest; init bridges I/O through protocol events over vsock.

### Linux — bubblewrap (`bwrap` backend)

```
Sandbox::start_vm()
  │
  ├─ socketpair(AF_UNIX, SOCK_SEQPACKET)     ← init control plane
  ├─ socketpair(AF_UNIX, SOCK_STREAM)         ← netstack (AllowAll only)
  │
  └─ exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts
                 --unshare-net                ← always: fresh netns
                 --ro-bind <.vm/base/rootfs>/{usr,bin,sbin,lib,lib64}
                 --ro-bind <.vm/base/rootfs>/etc/{passwd,group}
                 --ro-bind /etc/{resolv.conf,hosts,ssl,...}
                 --cap-add CAP_SYS_ADMIN      ← fusermount3
                 --cap-add CAP_NET_ADMIN      ← TAP + lo bringup
                 --cap-add CAP_NET_RAW        ← guest ping
                 --cap-add CAP_MKNOD          ← fallback TUN node creation
                 --dev-bind-try /dev/net/tun  ← AllowAll only
                 -- /path/to/tokimo-sandbox-init bwrap
                        --control-fd=<ctrl>
                        --net-fd=<net>        ← AllowAll only
                        --bringup-lo --mount-sysfs
                              │
                              └─ PID 2 inside bwrap (bwrap is PID 1)
                                 ├─ control: SEQPACKET, SCM_RIGHTS for PTY
                                 ├─ net: STREAM, TAP tk0 ↔ smoltcp on host
                                 └─ FUSE: socketpair per mount, FuseHost on host
```

- **No daemon, no service, no root.** Each `Sandbox` owns its own bwrap+init pair.
- **Packaged rootfs.** `/usr /bin /sbin /lib /lib64 /etc/passwd /etc/group` come from `.vm/base/rootfs/` (same artifact as macOS/Windows). Only network/DNS/CA config is bound from the host.
- **Networking:** Both `AllowAll` and `Blocked` use `--unshare-net` with a fresh netns. `AllowAll` layers smoltcp on top via TAP (`tk0`), bridged to host through STREAM socketpair. `Blocked` gets only `lo`.
- **File sharing:** All mounts use **FUSE-over-socketpair** — same `FuseHost` + `tokimo-sandbox-fuse` as macOS/Windows. Each mount gets an `AF_UNIX SOCK_STREAM` socketpair; host end served by `FuseHost`, guest end passed to `tokimo-sandbox-fuse` via `--transport unix-fd`.
- **PTY:** Master fd transferred to host via `SCM_RIGHTS` for direct I/O.

### macOS — Virtualization.framework

```
Sandbox::start_vm()
  │
  └─ arcbox-vz → VZVirtualMachine
       ├─ VZLinuxBootLoader(vmlinuz, initrd.img)
       ├─ VZVirtioFileSystemDevice  tag="rootfs"       ← rootfs (read-only)
       ├─ VZVirtioSocketDevice      port=2222          ← init control plane
       ├─ VZVirtioSocketDevice      port=4444          ← userspace netstack
       ├─ VZVirtioSocketDevice      port=5555          ← FUSE-over-vsock host
       └─ VZNetworkDeviceConfiguration::nat()          ← AllowAll only
            │
            └─ Linux micro-VM (arm64)
                 tokimo-sandbox-init (PID 1) over virtio-vsock
```

- **No service, no root.** Library-only; each `Sandbox` boots its own VM.
- **Shared filesystem:** All mounts use **FUSE-over-vsock** — host runs in-process `FuseHost` on vsock port 5555, each mount spawns a `tokimo-sandbox-fuse` child in guest that connects back via vsock. Same infrastructure as Linux and Windows.
- **Networking:** `AllowAll` uses host-side **smoltcp userspace netstack**. `Blocked` omits the network device.
- **PTY:** Master fd stays in guest; init bridges I/O through protocol events over vsock.

### Windows — Hyper-V HCS

```
Sandbox (library)  ──named pipe──▶  tokimo-sandbox-svc.exe (SYSTEM)
                                         │
                                         ├─ HCS compute system (Schema 2.5)
                                         │    ├─ LinuxKernelDirect(vmlinuz, initrd)
                                         │    ├─ SCSI: per-session rootfs.vhdx
                                         │    ├─ FUSE-over-vsock (user mounts)
                                         │    └─ HvSocket ServiceTable
                                         │
                                         ├─ AF_HYPERV listener (per-session GUID)
                                         │
                                         └─ smoltcp userspace netstack
                                              │
                                              └─ NAT → host network
```

- **SYSTEM service** manages VMs on behalf of unprivileged users. One-time install via `sudo ... --install` or MSIX.
- **Per-session isolation:** Each session gets a unique VHDX clone and HvSocket service GUID, supporting concurrent sessions.
- **Networking:** `AllowAll` uses the same **smoltcp userspace netstack** as macOS. `Blocked` sets `tokimo.net=blocked` in kernel cmdline.
- **PTY:** Same as macOS — master in guest, I/O bridged through protocol.

## Userspace network stack

All backends use the same **smoltcp-based L3/L4 proxy** (`src/net/netstack/`) for `NetworkPolicy::AllowAll`. One unified netstack, one interception point, regardless of platform or Linux backend choice.

```
Guest Linux kernel
  │ Ethernet frames
  │   Linux bwrap: via TAP tk0 → STREAM socketpair
  │   Linux ch:    via TAP tk0 → vsock UDS sidecar
  │   macOS:       via virtio-vsock
  │   Windows:     via HvSocket
  ▼
StreamDevice (smoltcp) on host
  │
  ├─ TCP: smoltcp socket → host TcpStream::connect() → bidirectional proxy
  ├─ UDP: smoltcp socket → host UdpSocket → manual Ethernet reply framing
  └─ ICMP: parse EchoRequest → OS-specific send_echo → fabricate EchoReply
```

- **Dual-stack IPv4/IPv6** with extension header walking (HopByHop, Route, Opts, Frag)
- **Subnet:** 192.168.127.0/24 (v4), fd00:7f::/64 (v6), MTU 1400
- **3 threads:** RX reader (transport → smoltcp), main poll loop, TX writer (smoltcp → transport)
- **120 s idle timeout** per flow

## Shared init binary (`tokimo-sandbox-init`)

A single Rust binary that runs as PID 1 (or PID 2 in bwrap) inside **every** sandbox on **every** platform. Auto-detects its transport at startup:

| Transport | Used by | PTY mechanism |
|---|---|---|
| `SOCK_SEQPACKET` (inherited fd) | Linux bwrap | `SCM_RIGHTS` fd transfer |
| VSOCK stream (guest connects) | Linux ch (hybrid-vsock) | Protocol bridge (Stdout/Write events) |
| VSOCK stream (guest listens) | macOS VZ | Protocol bridge (Stdout/Write events) |
| VSOCK stream (guest connects) | Windows HCS | Protocol bridge (Stdout/Write events) |

Capabilities: `Pipes` and `Pty` stdio modes, `Resize`, `Signal`, `Killpg`, `OpenShell`, `MountFuse`/`UnmountFuse` (FUSE-over-vsock/socketpair).

The host-side client is `src/init/client/` — generic over transport (`TransportSend`/`TransportRecv` traits). Each platform backend instantiates it with the appropriate transport (SEQPACKET for bwrap, VSOCKET for ch/macOS, pipe tunnel for Windows).

## Shared FUSE infrastructure (`FuseHost` + `tokimo-sandbox-fuse`)

All three platforms use the same FUSE-over-stream architecture for dynamic file sharing:

- **Host side** (`src/vfs/host/`): `FuseHost` accepts connections, dispatches FUSE ops to a `VfsBackend` implementation, writes responses. One `FuseHost` per sandbox session.
- **Guest side** (`tokimo-sandbox-fuse` binary): one process per mount. Connects to host (vsock or unix-fd), performs VFS Hello handshake, mounts a FUSE filesystem at the target path, translates kernel FUSE ops into wire `Req`s.
- **VFS protocol** (`src/vfs/protocol/`): postcard-encoded frames over length-prefixed stream. ~35 ops covering the full FUSE op table.
- **Built-in backends** (`src/vfs/impls/`): `LocalDirVfs` (host directory passthrough), `MemFsVfs` (in-memory, for tests).

## Host-Exec Bridge

Lets guest commands transparently invoke a host-side callback. The guest stub `tokimo-host-exec` is hardlinked under `/run/tokimo/host-bridge/<name>`. When executed inside the sandbox, it connects to the host (vsock or Unix socket), sends a `Spawn` with argv/env/cwd, and the host runs a user-registered callback or host-side process, pumping stdin/stdout/stderr bidirectionally.

- Host side: `src/host_exec/` — `HostExecBridge` with protocol state machine (Hello → Spawn → callback → RunOnHost/Reject).
- Guest side: `src/bin/tokimo-host-exec/` — connect + Hello + Spawn + pump.
- Protocol: `src/host_exec/protocol/` — postcard-based framing, version 1.

## Key source layout

| Path | Purpose |
|---|---|
| **`src/lib.rs`** | Crate root: declares 7 top-level modules, backward-compat re-export shims |
| **`src/api/`** | Public API module |
| `src/api/mod.rs` | `Sandbox` handle (~30 methods), `ConfigureParams`, `ShellOpts`, `Mount`, `NetworkPolicy`, `Event`, `HostExecCtx/Action/Callback`, `JobId`, `SessionSummary/Details`, `PortForwardSpec` |
| `src/api/backend.rs` | `SandboxBackend` trait — per-platform implementation contract |
| `src/api/backend_kind.rs` | `SandboxBackendKind` enum (`Auto`, `Disabled`, `Bwrap`, `Ch`), `ActiveBackend` enum |
| `src/api/error.rs` | `Error` enum + `Result<T>` alias + `bail!` macro |
| `src/api/platform.rs` | `default_backend()` — dispatches to OS-specific backend |
| **`src/backends/`** | Platform-specific backend implementations |
| `src/backends/mod.rs` | Conditional compilation: `linux`, `macos`, `shared`, `svc_protocol`, `windows` |
| `src/backends/shared.rs` | `SharedBackend<B>` — process-wide session sharing for in-process backends (Linux/macOS) |
| `src/backends/svc_protocol.rs` | Windows host ↔ service JSON-RPC: `Frame`, ~25 method names, typed param/result structs, `RootfsSpec` |
| `src/backends/linux/bwrap/sandbox.rs` | `LinuxBackend: SandboxBackend` — wraps bwrap in-process |
| `src/backends/linux/bwrap/init_client.rs` | InitClient over SOCK_SEQPACKET |
| `src/backends/linux/bwrap/init_transport.rs` | SEQPACKET framing + SCM_RIGHTS fd passing |
| `src/backends/linux/ch/backend.rs` | `ChBackend: SandboxBackend` — Cloud Hypervisor micro-VM |
| `src/backends/linux/ch/vmm.rs` | CH + virtiofsd child lifecycle |
| `src/backends/linux/ch/probe.rs` | `probe_ch()` — KVM/vsock/binary availability check |
| `src/backends/macos/sandbox.rs` | `MacosBackend: SandboxBackend` — boots VZ virtual machine |
| `src/backends/macos/vm.rs` | VZ VM lifecycle, `BOOT_LOCK` |
| `src/backends/macos/vsock_init_client.rs` | VsockInitClient (VSOCK transport) |
| `src/backends/windows/sandbox.rs` | `WindowsBackend: SandboxBackend` — forwards API calls as JSON-RPC over named pipe |
| `src/backends/windows/client.rs` | Named-pipe client: `WaitNamedPipeW` → `CreateFileW` |
| `src/backends/windows/init_client.rs` | Init client over transparent pipe tunnel |
| `src/backends/windows/init_transport.rs` | Windows init transport adapter |
| `src/backends/windows/ov_pipe.rs` | OVERLAPPED Read/Write wrapper |
| `src/backends/windows/safe_path.rs` | TOCTOU-safe `canonicalize_safe` |
| `src/backends/windows/ntfs_mode.rs` | NTFS mode-bit helpers |
| **`src/init/`** | Host-side init client + protocol (shared across all backends) |
| `src/init/client/mod.rs` | `InitClient<S: TransportSend>` — generic host-side client for `tokimo-sandbox-init` |
| `src/init/client/vsock.rs` | VSOCK transport implementation |
| `src/init/protocol/types.rs` | Host ↔ init wire protocol: `Frame`, `Op`, `Reply`, `Event`, `StdioMode` |
| `src/init/protocol/wire.rs` | Frame encode/decode, SEQPACKET + stream transport helpers |
| **`src/vfs/`** | VFS subsystem (FUSE-over-vsock/socketpair) |
| `src/vfs/backend.rs` | `VfsBackend` trait hierarchy: `VfsReader` + optional capability downcasts |
| `src/vfs/protocol/mod.rs` | VFS wire protocol: `Frame`, `Req` (~35 ops), `Res`, `Errno`, `Inval` |
| `src/vfs/protocol/wire.rs` | Length-prefixed postcard framing with bulk-bypass optimization |
| `src/vfs/protocol/handshake.rs` | Hello/HelloAck handshake (async + blocking) |
| `src/vfs/host/mod.rs` | `FuseHost`: accept loop, per-mount dispatch, `IdTable` |
| `src/vfs/host/id_table.rs` | Nodeid + fh allocator with refcounting |
| `src/vfs/host/ops/` | Per-op handlers: `dir.rs`, `file.rs`, `meta.rs`, `mutate.rs`, `xattr.rs` |
| `src/vfs/impls/local.rs` | `LocalDirVfs` — host directory passthrough |
| `src/vfs/impls/mem.rs` | `MemFsVfs` — in-memory filesystem for tests |
| **`src/net/`** | Networking |
| `src/net/constants.rs` | Shared topology constants (IPs, MACs, subnet, MTU) |
| `src/net/ifreq.rs` | Linux ioctl helpers for network interface configuration |
| `src/net/netstack/mod.rs` | Userspace smoltcp L3/L4 proxy (~1750 lines) |
| **`src/host_exec/`** | Host-Exec Bridge |
| `src/host_exec/mod.rs` | `HostExecBridge` — guest command → host callback bridge |
| `src/host_exec/protocol/` | Wire protocol: `Frame`, postcard-based framing |
| **`src/util/`** | Utilities |
| `src/util/affinity.rs` | CPU affinity helpers |
| `src/util/fonts.rs` | Host font directory discovery |
| `src/util/rootfs_init.rs` | Rootfs initialization helpers |
| `src/util/session_registry.rs` | `SessionRegistry` for Windows service |
| `src/util/vm_dir.rs` | VM directory management |
| **Binaries (`src/bin/`)** | |
| `src/bin/tokimo-sandbox-init/` | Guest PID 1 binary (all 3 platforms): transport dispatch, child mgmt, PTY, server loop, TUN pump, host-exec listener |
| `src/bin/tokimo-sandbox-fuse/` | Guest-side FUSE bridge: kernel FUSE ops → VFS wire reqs |
| `src/bin/tokimo-sandbox-svc/` | Windows SYSTEM service: SCM lifecycle, HCS, hvsock, netstack, VHDX pool |
| `src/bin/tokimo-tun-pump/` | Guest-side TUN ↔ vsock bridge (TAP `tk0` ↔ host netstack) |
| `src/bin/tokimo-host-exec/` | Guest-side host-exec stub: connect → Hello → Spawn → pump |

## Deployment modes (Windows)

- **MSIX** (`packaging/windows/`, `scripts/windows/build-msix.ps1`): recommended for production — registers service name `TokimoSandboxSvc` via `desktop6:Service`.
- **CLI install** (`--install` / `--uninstall`): registers service name `tokimo-sandbox-svc` (lowercase-kebab) — for development. The two names intentionally differ so both can coexist.
- **Console mode** (`--console`): foreground dev mode, no SCM registration needed.

## Windows APIs — all through the `windows` crate (verified)

**No hand-written FFI, no manual `extern "system"` blocks.** Every Win32 call goes through the `windows = "0.62"` crate. The exceptions are `ComputeCore.dll` (HCS API) and `computenetwork.dll` (HCN), loaded dynamically via the `windows` crate's own `LoadLibraryW` + `GetProcAddress`.

The verified API surface, grouped by file:

### `src/backends/windows/client.rs` (library-side named pipe client)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `ERROR_PIPE_BUSY`, `GENERIC_READ`, `GENERIC_WRITE`, `GetLastError` |
| `Win32_Security` | `SECURITY_ATTRIBUTES` |
| `Win32_Storage_FileSystem` | `CreateFileW`, `FILE_FLAGS_AND_ATTRIBUTES`, `FILE_SHARE_NONE`, `OPEN_EXISTING` |
| `Win32_System_Pipes` | `WaitNamedPipeW` |
| `windows::core` | `HSTRING` |
| std | `std::os::windows::io::FromRawHandle` |

### `src/backends/windows/ov_pipe.rs` (OVERLAPPED Read/Write wrapper)

| Crate feature | Items used |
|---|---|
| `Win32_Foundation` | `CloseHandle`, `DUPLICATE_SAME_ACCESS`, `DuplicateHandle`, `ERROR_BROKEN_PIPE`, `ERROR_HANDLE_EOF`, `ERROR_IO_PENDING`, `ERROR_PIPE_NOT_CONNECTED`, `GetLastError`, `HANDLE`, `WAIT_OBJECT_0` |
| `Win32_Storage_FileSystem` | `ReadFile`, `WriteFile` |
| `Win32_System_IO` | `GetOverlappedResult`, `OVERLAPPED` |
| `Win32_System_Threading` | `CreateEventW`, `GetCurrentProcess`, `INFINITE`, `WaitForSingleObject` |
| `windows::core` | `PCWSTR` |

### `src/backends/windows/safe_path.rs` (TOCTOU-safe canonicalization)

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

## Build & test

```powershell
# --- Windows ---

# Build everything
cargo build

# Console mode (dev, sudo required — runs in foreground, no SCM)
sudo cargo run --bin tokimo-sandbox-svc -- --console

# Install as SCM service (sudo, registers as "tokimo-sandbox-svc")
sudo .\target\debug\tokimo-sandbox-svc.exe --install
# Uninstall
.\target\debug\tokimo-sandbox-svc.exe --uninstall

# Tests
cargo test --lib
cargo test --bin tokimo-sandbox-svc --lib

# Package MSIX
pwsh ./scripts/windows/build-msix.ps1
```

```bash
# --- Linux ---

# One-time
sudo apt install bubblewrap

# Build guest binaries so bwrap/CH can exec them
cargo build --bin tokimo-sandbox-init --bin tokimo-sandbox-fuse --bin tokimo-tun-pump --bin tokimo-host-exec

# Full integration suite.
# --test-threads=1 keeps bwrap user-namespace creation rate sane.
# See tests/README.md for per-file inventory and platform docs.
PATH="$PWD/target/debug:$PATH" cargo test -- --test-threads=1
```

```bash
# --- macOS (Apple Silicon) ---

# 1. Provide VM artifacts under <repo>/.vm/base/:
#    Use scripts/macos/build-vm-local.sh or scripts/linux/fetch-vm.sh

# 2. Register the codesign cargo runner once (in your gitignored
#    .cargo/config.toml; the runner ad-hoc-signs each test binary with
#    packaging/macos/vz.entitlements before exec'ing):
#       [target.aarch64-apple-darwin]
#       runner = "scripts/macos/codesign-and-run.sh"
#       [target.x86_64-apple-darwin]
#       runner = "scripts/macos/codesign-and-run.sh"

# 3. Run. --test-threads=1 is required (the VZ dispatch queue cannot
#    handle parallel vm.start() calls from one process; BOOT_LOCK
#    enforces it inside the backend too).
cargo test -- --test-threads=1
```

See `docs/macos-testing.md` for the full setup walkthrough.

## Environment variables

| Variable | Purpose |
|---|---|
| `SAFEBOX_DISABLE=1` | Bypass sandbox entirely, run natively (debug escape hatch) |
| `SANDBOX_BACKEND` | Linux backend selection: `auto` (default), `ch`, `bwrap`, `disabled` |
| `TOKIMO_VERIFY_CALLER=1` | Enforce Authenticode verification of pipe clients (Windows service) |
| `TOKIMO_SANDBOX_PRE_CHROOTED=1` | VM modes: skip init's mount/chroot setup because `init.sh` already did it |

Linux/bwrap configuration is passed via argv (subcommand `tokimo-sandbox-init bwrap --control-fd=<n> [--bringup-lo] [--mount-sysfs]`) rather than env vars, so nothing leaks into spawned children.

## Windows VM artifacts

Windows requires three files (`vmlinuz`, `initrd.img`, `rootfs.vhdx`) in `<repo>/.vm/base/`. Built and published in-repo by `.github/workflows/vm.yml` under two independent tag namespaces: `vm-kernel-*` (vmlinuz + initrd, ships with each host crate version; the four guest binaries `tokimo-sandbox-init` / `tokimo-sandbox-fuse` / `tokimo-tun-pump` / `tokimo-host-exec` are baked into the initrd's `/bin/` and bind-mounted at runtime to `/run/tokimo/bin/` inside the rootfs) and `vm-rootfs-*` (pure Debian rootfs, no tokimo binaries, rarely rebuilt). See `packaging/vm-base/README.md` for the build pipeline. Download via:

```powershell
pwsh scripts/windows/fetch-vm.ps1                                                   # latest of each
pwsh scripts/windows/fetch-vm.ps1 -KernelTag vm-kernel-1.0.0 -RootfsTag vm-rootfs-1.0.0
```

## HvSocket concurrency — critical design note

Each session allocates a **unique vsock port** via `vmconfig::alloc_session_init_port()`, which encodes into a unique HvSocket service GUID (`{port:08X}-FACB-11E6-BD58-64006A7986D3`). This is required because:

1. Hyper-V requires `(VmId, ServiceId)` to be unique for host-side listeners.
2. The parent partition **must** use `HV_GUID_WILDCARD` as the listener VmId — binding a specific child's RuntimeId returns `WSAEACCES (10013)`.
3. Two wildcard listeners on the same ServiceId → `WSAEADDRINUSE (10048)`.

Therefore, the **only** way to run concurrent sessions is one `ServiceId` per session. Service GUIDs are registered via the HCS `ServiceTable` in the VM config JSON (no `HKLM` registry writes needed). The vsock port is passed to the guest kernel as `tokimo.init_port=<port>` on the cmdline.
