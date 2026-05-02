# tokimo-package-sandbox

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Cross-platform native sandbox library for running untrusted commands in isolated environments. One API, three platforms, each using the isolation primitive that is native to the OS.

| Platform | Isolation engine | Root privilege | Startup |
|---|---|---|---|
| **Linux** | bubblewrap (user namespaces) + smoltcp netstack | not required | ~50 ms |
| **macOS** | Apple Virtualization.framework → Linux micro-VM + smoltcp netstack | not required | ~2 s cold |
| **Windows** | Hyper-V HCS → Linux micro-VM + smoltcp netstack via SYSTEM service | one-time service install | ~600 ms |

All three backends present the same `Sandbox` handle with identical semantics: configure → create → start → spawn shells → stop. A single init binary (`tokimo-sandbox-init`) runs as PID 1 inside every sandbox, speaking the same wire protocol regardless of transport. Networking is unified: all three platforms use the same smoltcp userspace netstack for `AllowAll` policy.

## Why this project exists

Existing sandbox solutions are either platform-specific (bwrap, jail, WSL) or require a daemon and images (Docker, Podman). There is no open-source library that gives you a **single Rust API** to sandbox a command on Linux, macOS, and Windows — with working networking, PTY support, and dynamic host↔guest file sharing — without requiring root, Docker, or pre-built container images.

This project fills that gap.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Your application                       │
│                                                             │
│   let sb = Sandbox::connect().unwrap();                     │
│   sb.configure(params).unwrap();                            │
│   sb.start_vm().unwrap();                                   │
│   let r = sb.exec(&["uname", "-a"], ExecOpts::default());   │
│   sb.stop_vm().unwrap();                                    │
└────────────────────────┬────────────────────────────────────┘
                         │  same API on all platforms
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   LinuxBackend     MacosBackend    WindowsBackend
   (in-process)     (in-process)    (named-pipe RPC)
        │                │                │
        ▼                ▼                ▼
   bwrap + user     arcbox-vz →     tokimo-sandbox-svc
   namespaces       VZVirtualMachine    (SYSTEM service)
        │                │                │
        └────────┬───────┘                │
                 ▼                        ▼
        tokimo-sandbox-init       Hyper-V HCS compute system
        (PID 1, shared binary)           │
                 │                       │
                 ▼                       ▼
          Linux guest              Linux micro-VM
```

### Linux — bubblewrap + smoltcp, no VM

```
Sandbox::start_vm()
  │
  ├─ socketpair(AF_UNIX, SOCK_SEQPACKET)     ← init control plane
  ├─ socketpair(AF_UNIX, SOCK_STREAM)         ← netstack (AllowAll only)
  │
  └─ exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts
                 --unshare-net                ← always: fresh netns
                 --ro-bind /usr /bin /sbin /lib /lib64
                 --bind <workspace> /workspace
                 --cap-add CAP_SYS_ADMIN
                 --cap-add CAP_NET_ADMIN      ← for TAP + lo bringup
                 --cap-add CAP_NET_RAW        ← for guest ping
                 --cap-add CAP_MKNOD          ← fallback TUN node creation
                 --dev-bind-try /dev/net/tun  ← AllowAll only
                 -- /path/to/tokimo-sandbox-init bwrap
                        --control-fd=<ctrl>
                        --net-fd=<net>        ← AllowAll only
                        --bringup-lo --mount-sysfs
                              │
                              └─ PID 2 inside bwrap (bwrap is PID 1)
                                 ├─ control: SEQPACKET, SCM_RIGHTS for PTY
                                 └─ net: STREAM, TAP tk0 ↔ smoltcp on host
```

- **No daemon, no service, no root.** Each `Sandbox` owns its own bwrap+init pair.
- **Networking:** Both `AllowAll` and `Blocked` use `--unshare-net` with a fresh netns. `AllowAll` layers a userspace smoltcp netstack on top via a TAP device (`tk0`) inside the sandbox, bridged to the host through a STREAM socketpair — the same architecture as macOS and Windows. `Blocked` gets only `lo`.
- **Dynamic mounts:** Host fd sent via `SCM_RIGHTS` → init opens via `openat` into `/.tps_host` staging → bind-mount to guest path.
- **PTY:** Master fd transferred to host via `SCM_RIGHTS` for direct I/O.

### macOS — Virtualization.framework

```
Sandbox::start_vm()
  │
  └─ arcbox-vz → VZVirtualMachine
       ├─ VZLinuxBootLoader(vmlinuz, initrd.img)
       ├─ VZVirtioFileSystemDevice  tag="work"        ← rootfs (read-only)
       ├─ VZVirtioFileSystemDevice  tag="tokimo_dyn"   ← dynamic share pool
       ├─ VZVirtioSocketDevice      port=2222          ← init control plane
       ├─ VZVirtioSocketDevice      port=4444          ← userspace netstack
       └─ VZNetworkDeviceConfiguration::nat()          ← AllowAll only
            │
            └─ Linux micro-VM (arm64)
                 tokimo-sandbox-init (PID 1) over virtio-vsock
```

- **No service, no root.** Library-only; each `Sandbox` boots its own VM.
- **Shared filesystem:** virtio-fs (not Plan9). Static shares via `work` tag, dynamic shares via `tokimo_dyn` pool with APFS clone-on-copy.
- **Networking:** `AllowAll` uses a **userspace smoltcp netstack** on the host (see below). `Blocked` omits the network device entirely.
- **PTY:** Master fd stays in guest; init bridges I/O through protocol `Stdout`/`Write` events over vsock.

### Windows — Hyper-V HCS

```
Sandbox (library)  ──named pipe──▶  tokimo-sandbox-svc.exe (SYSTEM)
                                         │
                                         ├─ HCS compute system (Schema 2.5)
                                         │    ├─ LinuxKernelDirect(vmlinuz, initrd)
                                         │    ├─ SCSI: per-session rootfs.vhdx
                                         │    ├─ Plan9 shares via vsock 9p
                                         │    └─ HvSocket ServiceTable
                                         │
                                         ├─ AF_HYPERV listener (per-session GUID)
                                         │
                                         └─ smoltcp userspace netstack
                                              │
                                              └─ NAT → host network
```

- **SYSTEM service** manages VMs on behalf of non-admin users. One-time install via `--install` or MSIX.
- **Per-session isolation:** Each session gets a unique VHDX clone and HvSocket service GUID, supporting concurrent sessions.
- **Networking:** `AllowAll` uses the same **userspace smoltcp netstack** as macOS. `Blocked` sets `tokimo.net=blocked` in kernel cmdline.
- **PTY:** Same as macOS — master in guest, I/O bridged through protocol.

## Userspace network stack

All three backends use the same **smoltcp-based L3/L4 proxy** (`src/netstack/`) for `NetworkPolicy::AllowAll`. One unified netstack, one interception point, regardless of platform.

```
Guest Linux kernel
  │ Ethernet frames
  │   Linux:   via TAP tk0 → STREAM socketpair
  │   macOS:   via virtio-vsock
  │   Windows: via HvSocket
  ▼
StreamDevice (smoltcp) on host
  │
  ├─ TCP: smoltcp socket → host TcpStream::connect() → bidirectional proxy
  ├─ UDP: smoltcp socket → host UdpSocket → manual Ethernet reply framing
  └─ ICMP: parse EchoRequest → OS-specific send_echo → fabricate EchoReply
```

- **All three platforms** — Linux (TAP + socketpair), macOS (vsock), Windows (HvSocket)
- **Dual-stack IPv4/IPv6** with extension header walking (HopByHop, Route, Opts, Frag)
- **Subnet:** 192.168.127.0/24 (v4), fd00:7f::/64 (v6), MTU 1400
- **3 threads:** RX reader (transport → smoltcp), main poll loop, TX writer (smoltcp → transport)
- **120 s idle timeout** per flow

## Shared init binary

`tokimo-sandbox-init` is a single Rust binary that runs as PID 1 (or PID 2 in bwrap) inside every sandbox. It auto-detects its transport at startup:

| Transport | Used by | PTY mechanism |
|---|---|---|
| `SOCK_SEQPACKET` (inherited fd) | Linux bwrap | `SCM_RIGHTS` fd transfer |
| `SOCK_SEQPACKET` (listener) | Linux standalone | `SCM_RIGHTS` fd transfer |
| VSOCK stream (guest listens) | macOS VZ | Protocol bridge (Stdout/Write events) |
| VSOCK stream (guest connects) | Windows HCS | Protocol bridge (Stdout/Write events) |

Capabilities: `Pipes` and `Pty` stdio modes, `Resize`, `Signal`, `Killpg`, `OpenShell`, `AddUser`/`RemoveUser`, `BindMount`/`Unmount`, dynamic `AddMountFd`/`RemoveMountByName`, `MountManifest` (9p-over-vsock).

## Quick start

```toml
[dependencies]
tokimo-package-sandbox = "0.1"
```

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

sb.create_vm().unwrap();
sb.start_vm().unwrap();

let shell = sb.shell_id().unwrap();
sb.write_stdin(&shell, b"uname -a\n").unwrap();
// ... read events via sb.subscribe() ...

sb.stop_vm().unwrap();
```

## Prerequisites

| Platform | Requirement |
|---|---|
| **Linux** | `sudo apt install bubblewrap` — no root at runtime |
| **macOS** | macOS 13+, Apple Silicon. VM artifacts under `<repo>/vm/` (see below). Code-sign with `com.apple.security.virtualization` entitlement. |
| **Windows** | "Virtual Machine Platform" enabled (Win 10 1903+). One-time admin to install service. VM artifacts under `<repo>/vm/`. |

### VM artifacts (macOS & Windows)

Both platforms share the same Linux kernel + initrd + Debian 13 rootfs. Download via:

```powershell
pwsh scripts/windows/fetch-vm.ps1                 # latest release
pwsh scripts/windows/fetch-vm.ps1 -Tag vm-v1.9.0  # specific tag
```

Or symlink prebuilt arm64 artifacts for local macOS development:

```sh
mkdir -p vm
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/vmlinuz"    vm/vmlinuz
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/initrd.img" vm/initrd.img
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/rootfs"     vm/rootfs
```

### macOS code signing

Register the codesign cargo runner in your local `.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"
```

### Windows service

```powershell
# Development — foreground, no SCM
cargo run --bin tokimo-sandbox-svc -- --console

# Development — persistent SCM service (admin)
.\target\debug\tokimo-sandbox-svc.exe --install

# Production — MSIX
pwsh scripts/windows/build-msix.ps1
```

## What's inside the sandbox

All platforms run the same **Debian 13 (Trixie) Linux rootfs**:

| Category | Contents |
|---|---|
| **Runtimes** | Node.js 24, Python 3.13, Lua 5.4 |
| **Editors** | vim, nano |
| **Office / docs** | pandoc, libreoffice (headless), poppler, qpdf, tesseract-ocr |
| **Python** | pypdf, pdfplumber, reportlab, pandas, openpyxl, markitdown, ipython, requests, rich, Pillow |
| **Node.js** | pnpm, docx, pptxgenjs |
| **Media** | ffmpeg |
| **Network** | curl, wget, dig, ping, rsync, git |
| **Other** | jq, zstd, bash-completion |

## API

### Sandbox lifecycle

```rust
let sb = Sandbox::connect()?;
sb.configure(ConfigureParams { .. })?;
sb.create_vm()?;      // Windows: HCS compute system; Linux/macOS: no-op
sb.start_vm()?;       // Linux: spawn bwrap; macOS: boot VM; Windows: start HCS
sb.stop_vm()?;        // teardown
```

### Shell control

```rust
let shell = sb.shell_id()?;                          // default shell
let job = sb.spawn_shell(ShellOpts { pty: Some((24, 80)), .. })?;  // PTY shell
sb.write_stdin(&shell, b"echo hello\n")?;
sb.resize_shell(&job, 40, 120)?;
sb.signal_shell(&job, Signal::SIGTERM)?;
sb.close_shell(&job)?;
let shells = sb.list_shells()?;
```

### Events

```rust
let rx = sb.subscribe();
for event in rx {
    match event {
        Event::Stdout { id, data } => { /* stdout bytes */ }
        Event::Stderr { id, data } => { /* stderr bytes */ }
        Event::Exit { id, exit_code, signal } => { /* process exited */ }
        Event::GuestConnected => { /* guest init is ready */ }
        _ => {}
    }
}
```

### Dynamic file sharing

```rust
sb.add_mount(Mount {
    name: "workspace".into(),
    host_path: "/tmp/my-project".into(),
    guest_path: "/workspace".into(),
    read_only: false,
})?;
// ... guest can access /workspace ...
sb.remove_mount("workspace")?;
```

## Tests

24 integration tests exercising the real guest through the public `Sandbox` API. Platform-agnostic source; same suite runs on all three platforms.

```bash
# Linux
sudo apt install bubblewrap
cargo build --bin tokimo-sandbox-init
PATH="$PWD/target/debug:$PATH" cargo test --test sandbox_integration -- --test-threads=1

# macOS
cargo test --test sandbox_integration -- --test-threads=1

# Windows (elevated, service running)
cargo test --test sandbox_integration -- --nocapture
```

`--test-threads=1` is required on Linux (bwrap rate limits) and macOS (VZ dispatch queue serializes VM starts). Windows runs with concurrency.

Coverage: lifecycle, shell I/O, multi-shell streams + signals + enumeration, PTY size/resize/ctrl-c/escape codes, Plan9 share add/remove, network blocked/allow-all/ICMPv4/ICMPv6/IPv6 TCP, multi-session concurrency.

Unit tests: `cargo test --lib` (session registry, protocol, svc internals).

## Examples

```bash
# Interactive PTY shell in a sandbox
cargo run --example pty_shell

# smoltcp netstack standalone demo (TCP + UDP proxy without a VM)
cargo run --example smoltcp_netstack
```

## Source layout

```
src/
├── lib.rs                    Public surface, re-exports
├── api.rs                    Sandbox handle, ConfigureParams, Event, Mount
├── backend.rs                SandboxBackend trait (22 methods)
├── error.rs                  Error enum + Result alias
├── platform.rs               default_backend() per OS
├── session_registry.rs       Platform-agnostic session HashMap
├── svc_protocol.rs           Windows service JSON-RPC protocol
│
├── protocol/                 Host ↔ init wire protocol (shared across all backends)
│   ├── types.rs              Frame, Op, Reply, Event, StdioMode
│   └── wire.rs               Length-prefixed JSON + SCM_RIGHTS framing
│
├── netstack/                 Userspace smoltcp L3/L4 proxy (macOS + Windows)
│   ├── mod.rs                StreamDevice, TCP/UDP/ICMP flow proxy
│   └── icmp/                 OS-specific ICMP echo backends
│
├── linux/                    Linux backend (bwrap, in-process)
│   ├── sandbox.rs            LinuxBackend: SandboxBackend
│   └── init_client.rs        InitClient over SOCK_SEQPACKET
│
├── macos/                    macOS backend (Virtualization.framework)
│   ├── sandbox.rs            MacosBackend: SandboxBackend
│   ├── vm.rs                 VM bootstrap, BOOT_LOCK
│   └── vsock_init_client.rs  VsockInitClient over VSOCK stream
│
├── windows/                  Windows backend (HCS via SYSTEM service)
│   ├── sandbox.rs            WindowsBackend: SandboxBackend
│   ├── client.rs             Named-pipe JSON-RPC client
│   ├── init_client.rs        WinInitClient over HvSocket
│   ├── ov_pipe.rs            OVERLAPPED pipe wrapper
│   └── safe_path.rs          TOCTOU-safe path canonicalization
│
└── bin/
    ├── tokimo-sandbox-init/  PID 1 guest binary (all platforms)
    │   ├── main.rs           Transport dispatch, mount setup
    │   ├── server.rs         Event loop (mio::Poll)
    │   ├── child.rs          fork/exec helpers
    │   └── pty.rs            PTY allocation
    │
    ├── tokimo-sandbox-svc/   Windows SYSTEM service
    │   └── imp/
    │       ├── mod.rs        SCM lifecycle, pipe server, session handler
    │       ├── hcs.rs        ComputeCore.dll loader
    │       ├── hvsock.rs     AF_HYPERV socket helpers
    │       ├── vmconfig.rs   HCS Schema 2.5 JSON builder
    │       └── vhdx_pool.rs  Per-session VHDX leasing
    │
    └── tokimo-tun-pump/      Guest-side TUN pump binary
```

## Network policies

| Policy | Behavior |
|---|---|
| `AllowAll` (default) | Full network access via **smoltcp userspace netstack** (all platforms). Linux: TAP + socketpair. macOS: vsock. Windows: HvSocket. |
| `Blocked` | No network. Linux: new netns with only `lo`. macOS: no NIC in VM config. Windows: `tokimo.net=blocked` kernel param. |

## Comparison with Docker

| | tokimo-package-sandbox | Docker |
|---|---|---|
| **Daemon** | none (library call; SYSTEM service on Windows) | dockerd required |
| **Startup** | ~50 ms (Linux) / ~2 s cold (macOS/Windows VM) | ~1-3 s |
| **Root** | not required (Linux/macOS) | typically required |
| **Images** | none (ships Debian rootfs) | required |
| **API** | Rust native, `Sandbox` handle | CLI / REST |
| **Networking** | unified smoltcp userspace netstack (all platforms) | bridge + iptables NAT |
| **Use case** | "run this untrusted command" | "deploy this service stack" |

## License

MIT. See [LICENSE](./LICENSE).
