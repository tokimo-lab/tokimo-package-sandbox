# tokimo-package-sandbox

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Cross-platform native sandbox library for running untrusted commands in isolated environments. One API, three platforms, each using the isolation primitive that is native to the OS.

| Platform | Isolation engine | Root privilege | Notes |
|---|---|---|---|
| **Linux (`ch`)** | Cloud Hypervisor micro-VM (KVM) + virtiofsd + smoltcp netstack | not required (membership in `kvm` group) | Preferred when `/dev/kvm` + `/dev/vhost-vsock` + `cloud-hypervisor` binary are available |
| **Linux (`bwrap`)** | bubblewrap (user namespaces) + smoltcp netstack | not required | Auto-fallback when CH is unavailable; ~50 ms start, no VM |
| **macOS** | Apple Virtualization.framework → Linux micro-VM + smoltcp netstack | not required | ~2 s cold |
| **Windows** | Hyper-V HCS → Linux micro-VM + smoltcp netstack via SYSTEM service | one-time service install | ~600 ms |

All backends present the same `Sandbox` handle with identical semantics: configure → create → start → spawn shells → stop. A single init binary (`tokimo-sandbox-init`) runs as PID 1 (or PID 2 inside bwrap) in every sandbox, speaking the same wire protocol regardless of transport. Networking is unified: every backend uses the same smoltcp userspace netstack for `AllowAll`.

**Linux backend selection** (`SANDBOX_BACKEND` env):

| Value           | Behavior                                                                 |
|-----------------|--------------------------------------------------------------------------|
| (unset) / `auto`| Probe `ch` first; gracefully fall back to `bwrap` if CH is unavailable.  |
| `ch`            | Force Cloud Hypervisor; fail (no fallback) if unavailable.               |
| `bwrap`         | Force bubblewrap; fail if unavailable.                                   |
| `disabled`      | Refuse to construct any backend.                                         |

`Sandbox::active_backend()` returns the concrete backend chosen at runtime so callers / CI can confirm which path was selected.

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

The Linux platform layer probes for Cloud Hypervisor at `Sandbox::connect()` time and picks the strongest backend that works on the host. CH is preferred (real KVM isolation, full kernel boundary, identical posture to macOS/Windows); bwrap is the fallback (no VM, fastest startup, works in environments without `/dev/kvm` such as nested CI without virtualization).

Both backends share **everything except the isolation primitive**: the same `tokimo-sandbox-init` PID 1 binary, the same `FuseHost`/`tokimo-sandbox-fuse` FUSE infrastructure, the same smoltcp netstack, the same protocol frames. Only the transport wiring differs (SEQPACKET socketpairs vs. hybrid-vsock UDS sidecars).

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
- **vsock transport** uses CH's *hybrid-vsock* — host plays the vsock by listening on per-port UDS files (`<vsock_uds>_<port>`) instead of `/dev/vhost-vsock`. All four channels (init, netstack, FUSE, console) are guest-initiated (`tokimo.guest_listens=0`).
- **File sharing** uses `virtiofsd` rather than the FUSE-over-vsock bridge for ConfigureParams mounts (it's the natural CH primitive). Runtime `add_mount` still uses FUSE-over-vsock through the same `FuseHost` as the other backends.
- **Networking:** `AllowAll` uses the same smoltcp userspace netstack as every other backend. `Blocked` omits the network device.
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
                 --ro-bind <.vm/base/rootfs>/etc/{passwd,group}     ← packaged user table
                 --ro-bind /etc/{resolv.conf,hosts,ssl,...}   ← host network/CA only
                 --cap-add CAP_SYS_ADMIN      ← for fusermount3
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
                                 ├─ net: STREAM, TAP tk0 ↔ smoltcp on host
                                 └─ FUSE: socketpair per mount, FuseHost on host
```

- **No daemon, no service, no root.** Each `Sandbox` owns its own bwrap+init pair.
- **Packaged rootfs.** `/usr /bin /sbin /lib /lib64 /etc/passwd /etc/group` come from `.vm/base/rootfs/` (the same artifact macOS and Windows boot from), so the in-sandbox tool versions are the same on every platform. Only network/DNS/CA config is bound from the host.
- **Networking:** Both `AllowAll` and `Blocked` use `--unshare-net` with a fresh netns. `AllowAll` layers a userspace smoltcp netstack on top via a TAP device (`tk0`) inside the sandbox, bridged to the host through a STREAM socketpair — the same architecture as macOS and Windows. `Blocked` gets only `lo`.
- **File sharing:** All mounts use **FUSE-over-socketpair** — the same `FuseHost` + `tokimo-sandbox-fuse` infrastructure as macOS and Windows. Each mount gets a `AF_UNIX SOCK_STREAM` socketpair; the host end is served by `FuseHost`, the guest end is passed to `tokimo-sandbox-fuse` via `--transport unix-fd`. Boot-time and runtime mounts use the same mechanism.
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
- **Shared filesystem:** All mounts use **FUSE-over-vsock** — the host runs an in-process `FuseHost` listening on vsock port 5555, each mount spawns a `tokimo-sandbox-fuse` child in the guest that connects back via vsock. Same infrastructure as Linux and Windows.
- **Networking:** `AllowAll` uses a **userspace smoltcp netstack** on the host (see below). `Blocked` omits the network device entirely.
- **PTY:** Master fd stays in guest; init bridges I/O through protocol `Stdout`/`Write` events over vsock.

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
- **Networking:** `AllowAll` uses the same **userspace smoltcp netstack** as macOS. `Blocked` sets `tokimo.net=blocked` in kernel cmdline.
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

- **All backends** — Linux bwrap (TAP + socketpair), Linux ch (TAP + vsock), macOS (vsock), Windows (HvSocket)
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
| VSOCK stream (guest connects) | Linux ch (hybrid-vsock) | Protocol bridge (Stdout/Write events) |
| VSOCK stream (guest listens) | macOS VZ | Protocol bridge (Stdout/Write events) |
| VSOCK stream (guest connects) | Windows HCS | Protocol bridge (Stdout/Write events) |

Capabilities: `Pipes` and `Pty` stdio modes, `Resize`, `Signal`, `Killpg`, `OpenShell`, `MountFuse`/`UnmountFuse` (FUSE-over-vsock/socketpair).

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
| **Linux** | For `bwrap`: `sudo apt install bubblewrap`. For `ch`: `cloud-hypervisor` + `virtiofsd` binaries on `PATH` (or under `bin/cloud-hypervisor/current/bin/` and `bin/virtiofsd/current/`), `/dev/kvm` + `/dev/vhost-vsock` accessible (typically requires the user to be in the `kvm` group). VM artifacts under `<repo>/.vm/base/`. No root at runtime in either case. |
| **macOS** | macOS 13+, Apple Silicon. VM artifacts under `<repo>/.vm/base/` (see below). Code-sign with `com.apple.security.virtualization` entitlement. |
| **Windows** | "Virtual Machine Platform" enabled (Win 10 1903+). One-time `sudo` to install service. VM artifacts under `<repo>/.vm/base/`. |

### VM artifacts (all platforms)

All three backends share the same Linux kernel + initrd + Debian 13 rootfs. The kernel/initrd and the rootfs are released under independent tag namespaces (`vm-kernel-*` ships with each host crate version; `vm-rootfs-*` rebuilds rarely). Download via:

```sh
# Linux / WSL
scripts/linux/fetch-vm.sh                                    # latest of each
scripts/linux/fetch-vm.sh -k vm-kernel-1.0.0 -r vm-rootfs-1.0.0  # pinned
```

```powershell
# Windows
pwsh scripts/windows/fetch-vm.ps1                                          # latest of each
pwsh scripts/windows/fetch-vm.ps1 -KernelTag vm-kernel-1.0.0 -RootfsTag vm-rootfs-1.0.0
```

Or build locally for macOS:

```sh
scripts/macos/build-vm-local.sh              # arm64 (default)
```

### Local initrd rebake (after editing init.sh or guest binaries)

The published initrd is built by CI (`vm.yml` → `build.sh`) and is the
single source of truth for kernel + modules + rootfs. When iterating on
`init.sh` or the three musl guest binaries (`tokimo-sandbox-init`,
`tokimo-tun-pump`, `tokimo-sandbox-fuse`) you can swap them into a copy
of the published initrd without re-running the full pipeline:

```sh
# Linux
scripts/linux/rebake-initrd.sh --install-to-vm

# macOS (exec's the Linux script — guest bins are always Linux musl)
scripts/macos/rebake-initrd.sh --install-to-vm
```

```powershell
# Windows (pwsh → wsl bash)
pwsh scripts/windows/rebake-initrd.ps1 -InstallToVm
```

All three accept the same flags: `--skip-build`, `--install-to-vm`,
`--arch amd64|arm64`, `--base <path>`. The rebake never touches
`/modules/` — kernel modules ship from CI with vermagic locked to the
shipped `vmlinuz`, and the script verifies this with a vermagic
self-check on the just-built initrd.

### macOS code signing

Register the codesign cargo runner in your local `.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"
```

### Windows service

```powershell
# Development — foreground, no SCM
sudo cargo run --bin tokimo-sandbox-svc -- --console

# Development — persistent SCM service (sudo)
sudo .\target\debug\tokimo-sandbox-svc.exe --install

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

34 integration tests exercising the real guest through the public `Sandbox` API. Platform-agnostic source; same suite runs on all three platforms.

```bash
# Linux — bwrap backend
sudo apt install bubblewrap
cargo build --bin tokimo-sandbox-init
SANDBOX_BACKEND=bwrap PATH="$PWD/target/debug:$PATH" \
    cargo test --test sandbox_integration -- --test-threads=1

# Linux — ch backend (KVM micro-VM; needs cloud-hypervisor + virtiofsd + /dev/kvm)
SANDBOX_BACKEND=ch PATH="$PWD/target/debug:$PATH" \
    cargo test --test sandbox_integration -- --test-threads=1

# macOS
cargo test --test sandbox_integration -- --test-threads=1

# Windows (sudo, service running)
sudo cargo test --test sandbox_integration -- --nocapture
```

`--test-threads=1` is required on Linux (bwrap user-namespace rate limits; CH boot serialization) and macOS (VZ dispatch queue serializes VM starts). Windows runs with concurrency.

Coverage: lifecycle, shell I/O, multi-shell streams + signals + enumeration, PTY size/resize/ctrl-c/escape codes, FUSE mount add/remove, network blocked/allow-all/ICMPv4/ICMPv6/IPv6 TCP, multi-session concurrency.

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
├── lib.rs                        Crate root: 7 top-level modules, re-export shims
│
├── api/                          Public Sandbox API
│   ├── mod.rs                    Sandbox handle (~30 methods), ConfigureParams, ShellOpts,
│   │                             Mount, NetworkPolicy, Event, HostExecCtx/Action/Callback,
│   │                             JobId, SessionSummary/Details, PortForwardSpec
│   ├── backend.rs                SandboxBackend trait — per-platform implementation contract
│   ├── backend_kind.rs           SandboxBackendKind (Auto/Disabled/Bwrap/Ch), ActiveBackend
│   ├── error.rs                  Error enum + Result alias + bail! macro
│   └── platform.rs               default_backend() per OS
│
├── backends/                     Platform-specific backend implementations
│   ├── mod.rs                    Conditional compilation: linux, macos, shared, svc_protocol, windows
│   ├── shared.rs                 SharedBackend<B> — process-wide session sharing (Linux/macOS)
│   ├── svc_protocol.rs           Windows host ↔ service JSON-RPC protocol
│   ├── linux/
│   │   ├── bwrap/                bubblewrap backend (no VM, namespaces only)
│   │   │   ├── sandbox.rs        LinuxBackend: SandboxBackend
│   │   │   ├── init_client.rs    InitClient over SOCK_SEQPACKET
│   │   │   └── init_transport.rs SEQPACKET framing + SCM_RIGHTS
│   │   └── ch/                   Cloud Hypervisor micro-VM backend
│   │       ├── backend.rs        ChBackend: SandboxBackend
│   │       ├── vmm.rs            CH + virtiofsd child lifecycle
│   │       └── probe.rs          probe_ch() — KVM/vsock/binary check
│   ├── macos/
│   │   ├── sandbox.rs            MacosBackend: SandboxBackend
│   │   ├── vm.rs                 VZ VM lifecycle, BOOT_LOCK
│   │   └── vsock_init_client.rs  VsockInitClient (VSOCK transport)
│   └── windows/
│       ├── sandbox.rs            WindowsBackend: SandboxBackend (JSON-RPC over named pipe)
│       ├── client.rs             Named-pipe client
│       ├── init_client.rs        Init client over transparent pipe tunnel
│       ├── init_transport.rs     Windows init transport adapter
│       ├── ov_pipe.rs            OVERLAPPED Read/Write wrapper
│       ├── safe_path.rs          TOCTOU-safe canonicalize_safe
│       └── ntfs_mode.rs          NTFS mode-bit helpers
│
├── init/                         Host-side init client + protocol (shared across all backends)
│   ├── client/
│   │   ├── mod.rs                InitClient<S: TransportSend> — generic host-side client
│   │   └── vsock.rs              VSOCK transport implementation
│   └── protocol/
│       ├── types.rs              Frame, Op, Reply, Event, StdioMode
│       └── wire.rs               Frame encode/decode, SEQPACKET + stream helpers
│
├── vfs/                          VFS subsystem (FUSE-over-vsock/socketpair)
│   ├── backend.rs                VfsBackend trait hierarchy + VfsFileInfo
│   ├── protocol/
│   │   ├── mod.rs                VFS wire protocol: Frame, Req (~35 ops), Res, Errno
│   │   ├── wire.rs               Length-prefixed postcard framing + bulk-bypass
│   │   └── handshake.rs          Hello/HelloAck handshake
│   ├── host/
│   │   ├── mod.rs                FuseHost: accept loop, per-mount dispatch
│   │   ├── id_table.rs           Nodeid + fh allocator with refcounting
│   │   └── ops/                  Per-op handlers: dir, file, meta, mutate, xattr
│   └── impls/
│       ├── local.rs              LocalDirVfs — host directory passthrough
│       ├── mem.rs                MemFsVfs — in-memory filesystem for tests
│       ├── meta.rs               meta_to_info() helper
│       ├── sanitize.rs           Path sanitization
│       └── macos_xattr.rs        macOS xattr handling
│
├── net/                          Networking
│   ├── constants.rs              Shared topology constants (IPs, MACs, subnet, MTU)
│   ├── ifreq.rs                  Linux ioctl helpers
│   └── netstack/
│       ├── mod.rs                Userspace smoltcp L3/L4 proxy (~1750 lines)
│       ├── host_dns.rs           Host DNS resolver detection
│       └── icmp/                 OS-specific ICMP echo backends
│
├── host_exec/                    Host-Exec Bridge (guest commands → host callback)
│   ├── mod.rs                    HostExecBridge, BridgeStream trait, handle_one()
│   ├── linux_relay.rs            SCM_RIGHTS relay reader thread
│   ├── macos_listener.rs         vsock accept loop
│   ├── transport.rs              Transport abstractions
│   └── protocol/
│       ├── mod.rs                Wire protocol: Frame enum, version 1
│       └── wire.rs               Postcard-based framing
│
├── util/                         Utilities
│   ├── affinity.rs               CPU affinity helpers
│   ├── fonts.rs                  Host font directory discovery
│   ├── raw_io.rs                 Low-level I/O helpers (Unix)
│   ├── rootfs_init.rs            Rootfs initialization
│   ├── session_registry.rs       SessionRegistry (Windows service)
│   ├── vm_dir.rs                 VM directory management
│   └── vsock_util.rs             VSOCK connection helpers (Linux)
│
└── bin/
    ├── tokimo-sandbox-init/      Guest PID 1 binary (all 3 platforms)
    │   ├── main.rs               Transport dispatch, mount setup, chroot
    │   ├── server.rs             Main request loop (mio::Poll)
    │   ├── child.rs              Child process management
    │   ├── pty.rs                PTY allocation
    │   └── pump.rs               TUN ↔ vsock bridge
    │
    ├── tokimo-sandbox-fuse/      Guest-side FUSE bridge binary
    │   └── main.rs               Kernel FUSE ops → VFS wire reqs
    │
    ├── tokimo-sandbox-svc/       Windows SYSTEM service
    │   └── imp/
    │       ├── mod.rs            SCM lifecycle, pipe server, session handler
    │       ├── hcs.rs            ComputeCore.dll loader
    │       ├── hvsock.rs         AF_HYPERV socket helpers
    │       ├── vmconfig.rs       HCS Schema 2.5 JSON builder
    │       ├── vhdx_pool.rs      Per-session VHDX leasing
    │       ├── netstack.rs       smoltcp userspace netstack
    │       └── svclog.rs         Logging
    │
    ├── tokimo-tun-pump/          Guest-side TUN ↔ vsock bridge
    └── tokimo-host-exec/         Guest-side host-exec stub
```

## Network policies

| Policy | Behavior |
|---|---|
| `AllowAll` (default) | Full network access via **smoltcp userspace netstack** (all backends). Linux bwrap: TAP + socketpair. Linux ch: TAP + vsock. macOS: vsock. Windows: HvSocket. |
| `Blocked` | No network. Linux bwrap: new netns with only `lo`. Linux ch: no NIC in CH config. macOS: no NIC in VM config. Windows: `tokimo.net=blocked` kernel param. |

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
