# tokimo-package-sandbox

[![Crates.io](https://img.shields.io/crates/v/tokimo-package-sandbox.svg)](https://crates.io/crates/tokimo-package-sandbox)
[![Docs.rs](https://docs.rs/tokimo-package-sandbox/badge.svg)](https://docs.rs/tokimo-package-sandbox)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![CI](https://github.com/tokimo-lab/tokimo-package-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/tokimo-lab/tokimo-package-sandbox/actions/workflows/ci.yml)

Cross-platform native sandbox for executing untrusted commands safely.

| Platform | Engine | Isolation level |
|---|---|---|
| **Linux** | bubblewrap + seccomp BPF + cgroups | strong — user/PID/mount/net/UTS namespaces |
| **macOS** | Virtualization.framework → Linux VM | strong — full Linux namespaces + seccomp inside VM |
| **Windows** | Hyper-V (HCS) → Linux VM via SYSTEM service | strong — full Linux namespaces + seccomp inside VM |

## Quick start

```toml
[dependencies]
tokimo-package-sandbox = "0.1"
```

```rust
use tokimo_package_sandbox::{SandboxConfig, NetworkPolicy, ResourceLimits};

let work = tempfile::tempdir()?;

let cfg = SandboxConfig::new(work.path())
    .network(NetworkPolicy::Blocked)
    .limits(ResourceLimits {
        max_memory_mb: 256,
        timeout_secs: 30,
        max_file_size_mb: 16,
        max_processes: 64,
    });

let out = tokimo_package_sandbox::run(&["rm", "-rf", "/"], &cfg)?;
// Host filesystem untouched — exit_code != 0
```

## Prerequisites

| Platform | Requirement |
|---|---|
| **Linux** | `sudo apt install bubblewrap` (firejail fallback) |
| **macOS** | Linux kernel + initrd + rootfs from this repo's `vm-v*` GitHub releases (built by `.github/workflows/vm-image.yml`) |
| **Windows** | Enable "Virtual Machine Platform" in Windows Features (Win 10 1903+, all editions). One-time UAC to install the SYSTEM service. |

## What's inside the sandbox

All platforms run the same **Debian 13 (Trixie) Linux rootfs** with pre-installed tooling:

| Category | Contents |
|---|---|
| **Runtimes** | Node.js 24, Python 3.13, Lua 5.4 |
| **Editors** | vim, nano |
| **Office / docs** | pandoc, libreoffice (headless), poppler, qpdf, tesseract-ocr |
| **Python pkgs** | pypdf, pdfplumber, reportlab, pandas, openpyxl, markitdown, ipython, requests, rich, Pillow |
| **Node.js global** | pnpm, docx, pptxgenjs |
| **Media** | ffmpeg |
| **Network** | curl, wget, dig, ping, rsync, git |
| **Other** | jq, zstd, bash-completion |

VM artifacts (kernel + initrd + Debian rootfs) are built in-repo by a two-layer
CI pipeline (`.github/workflows/vm-base.yml` + `vm-image.yml`, see
[`packaging/vm-image/README.md`](packaging/vm-image/README.md)) and published
under tags with prefix `vm-v*`. The same release feeds both macOS and Windows.

## macOS setup

The macOS backend boots a lightweight Linux VM via Virtualization.framework (macOS 11+).

```bash
# 1. Download artifacts (replace x86_64 with arm64 on Apple Silicon? — both are
#    built; pick whichever matches the host arch you'll boot the guest under)
BASE=https://github.com/tokimo-lab/tokimo-package-sandbox/releases/latest/download
curl -LO $BASE/tokimo-linux-kernel-arm64.tar.zst
curl -LO $BASE/tokimo-linux-rootfs-arm64.tar.zst

# 2. Extract to ~/.tokimo/
zstd -d tokimo-linux-kernel-arm64.tar.zst && tar -xpf tokimo-linux-kernel-arm64.tar -C ~/.tokimo/
mkdir -p ~/.tokimo/rootfs
zstd -d tokimo-linux-rootfs-arm64.tar.zst && tar -xpf tokimo-linux-rootfs-arm64.tar -C ~/.tokimo/rootfs/

# 3. Sign the binary with virtualization entitlement
codesign --entitlements vz.entitlements --force -s - target/debug/your-app

# 4. Run
./your-app
```

Entitlement (`vz.entitlements`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.virtualization</key><true/>
</dict></plist>
```

Env vars: `TOKIMO_VZ_KERNEL`, `TOKIMO_VZ_INITRD`, `TOKIMO_VZ_ROOTFS`, `TOKIMO_VZ_MEMORY`, `TOKIMO_VZ_CPUS`.

## Windows setup

### Windows setup

The Windows backend runs a **SYSTEM-level service** (`tokimo-sandbox-svc.exe`) that creates Hyper-V VMs on behalf of non-admin users. Each `Session::open()` call:

1. Boots an isolated micro-VM (kernel + initrd + per-session VHDX clone)
2. Connects host ↔ guest via AF_HYPERV/HvSocket (per-session service GUID)
3. Bridges the init control protocol over a named pipe to the library

Multiple concurrent sessions are supported — each gets its own VM and unique HvSocket service GUID.

For a detailed architecture reference, see [`docs/windows-architecture.md`](docs/windows-architecture.md).

### 1. Enable Virtual Machine Platform

Open **Windows Features** → check **Virtual Machine Platform** → restart.

### 2. Install VM artifacts

VM artifacts (kernel + initrd + rootfs.vhdx) are produced by the in-repo
[`vm-image.yml`](.github/workflows/vm-image.yml) workflow and published under
tags with prefix `vm-v*`. Download into `<repo>/vm/` via:

```powershell
pwsh scripts/fetch-vm.ps1                 # latest release
pwsh scripts/fetch-vm.ps1 -Tag vm-v1.9.0  # specific tag
```

Expected layout:
```
<repo>/vm/
  vmlinuz             ← Linux kernel
  initrd.img          ← initramfs (busybox + Hyper-V modules + tokimo-sandbox-init)
  rootfs.vhdx         ← Debian 13 ext4 VHDX
```

### 3. Install service and run

**Development (console mode — foreground, no SCM):**

```powershell
cargo build --bin tokimo-sandbox-svc
# Run as administrator:
.\target\debug\tokimo-sandbox-svc.exe --console
```

**Development (SCM service — persistent, survives shell exit):**

```powershell
# Install and start as "tokimo-sandbox-svc" (admin required, one-time)
.\target\debug\tokimo-sandbox-svc.exe --install
# Verify
Get-Service tokimo-sandbox-svc  # Status = Running

# Uninstall when done
.\target\debug\tokimo-sandbox-svc.exe --uninstall
```

> If `--install` reports `(os error 1078)`, an MSIX-packaged instance is already installed (same display name). Remove it first: `Get-AppxPackage Tokimo.SandboxSvc | Remove-AppxPackage`

**Production (MSIX — registers service `TokimoSandboxSvc` via `desktop6:Service`):**

```powershell
pwsh scripts/build-msix.ps1
# Then double-click the .msix or deploy via MDM/WinGet
```

## Crate structure

```
src/
├── lib.rs                  ── public surface + cross-platform `run()`
├── config.rs               ── SandboxConfig / Mount / NetworkPolicy / ResourceLimits
├── error.rs                ── Error / Result / ExecutionResult
├── session.rs              ── Session / JobHandle / PtyHandle (platform dispatch)
│
├── protocol/               ── init control protocol (host ↔ tokimo-sandbox-init)
│   ├── types.rs            ──   Op / Result / Event / wire frames
│   └── wire.rs             ──   length-prefixed JSON + SCM_RIGHTS framing
│
├── host/                   ── host-side cross-platform helpers
│   ├── common.rs           ──   pipe_stdio / spawn_run / rlimits  (Unix)
│   ├── pty.rs              ──   master PTY allocation + raw-mode  (macOS)
│   └── net_observer.rs     ──   L7 HTTP(S) proxy + DnsPolicy + NetEvent sinks
│
├── linux/                  ── Linux backend (bwrap + seccomp + cgroups)
│   ├── mod.rs              ──   run() / spawn_init() / SpawnedInit
│   ├── bridge.rs           ──   L4 ↔ L7 verdict bridge
│   ├── seccomp.rs          ──   BPF program codegen
│   ├── init_client.rs      ──   host-side InitClient (SOCK_SEQPACKET)
│   └── l4/                 ──   seccomp-notify + seccomp-trace + scaffold eBPF observer
│
├── macos/                  ── macOS backend (Virtualization.framework)
│   ├── mod.rs              ──   run() / spawn_session_shell()
│   ├── vz.rs               ──   one-shot VM (kernel + initrd + virtiofs)
│   ├── vz_session.rs       ──   persistent VM runner
│   └── vz_vsock.rs         ──   InitClient over VSOCK
│
├── windows/                ── Windows backend (HCS via SYSTEM service)
│   ├── mod.rs              ──   run() → client::exec_vm()
│   ├── client.rs           ──   named-pipe client to tokimo-sandbox-svc
│   └── protocol.rs         ──   wire types (re-exported as `svc_protocol`)
│
├── workspace/              ── multi-user Workspace (Linux + macOS)
│   ├── mod.rs              ──   Workspace / UserHandle / UserConfig
│   └── any_init.rs         ──   AnyInitClient enum (Linux | macOS)
│
└── bin/
    ├── tokimo-sandbox-init/  ── PID 1 inside the Linux/VM container
    │   ├── main.rs           ──   transport dispatch (SOCK_SEQPACKET / VSOCK)
    │   ├── server.rs         ──   protocol loop
    │   ├── child.rs          ──   spawn / waitpid / pidfd
    │   └── pty.rs            ──   slave PTY setup
    │
    └── tokimo-sandbox-svc/   ── Windows SYSTEM service for HCS VM lifecycle
        └── main.rs           ──   reuses `svc_protocol` types from the lib
```

Public re-exports (see `lib.rs`): `SandboxConfig`, `Mount`, `NetworkPolicy`, `ResourceLimits`,
`SystemLayout`, `Session`, `JobHandle`, `PtyHandle`, `RunOneshotFn`, `OpenPtyFn`, `ExecOutput`,
`Workspace`, `WorkspaceConfig`, `UserConfig`, `UserHandle`, `Error`, `Result`, `ExecutionResult`,
`NetEvent`, `NetEventSink`, `Verdict`, `Layer`, `Proto`, `DnsPolicy`, `HostPattern`,
`SpawnedInit`, `spawn_init`, `locate_init_binary`, `InitClient`, `SpawnInfo`,
`generate_bpf_bytes`, `protocol::{types, wire}`, `svc_protocol` (Windows only).

## Architecture

### Linux

```
host process
  │
  ├─ Session / run()
  │     │
  │     ├─ Session::open() → spawn_init() → bwrap --as-pid-1 --unshare-all
  │     │     │
  │     │     ├─ tokimo-sandbox-init (PID 1) ← SOCK_SEQPACKET control socket
  │     │     │     ├─ Op::OpenShell  → bash REPL
  │     │     │     ├─ Op::Spawn      → child (pipes or PTY)
  │     │     │     └─ Event::Exit    → exit code + signal
  │     │     │
  │     │     ├─ Session::exec()   → sentinel protocol over bash stdio
  │     │     ├─ Session::spawn()  → init pipe mode (cwd/env inheritance)
  │     │     └─ Session::open_pty() → PTY master fd via SCM_RIGHTS
  │     │
  │     └─ run() → bwrap + seccomp BPF → one-shot → ExecutionResult
  │
  └─ Sensitive host dotfiles (~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker)
     are tmpfs-blanked even if $HOME is mounted.
```

### macOS

```
macOS host
  │
  ├─ run() → VzSandbox::boot(cfg)
  │     │
  │     ├─ VirtualMachineConfiguration
  │     │     ├─ LinuxBootLoader(kernel, initrd)  ← cmd_b64 via kernel cmdline
  │     │     ├─ VirtioFileSystem("work")          ← rootfs shared via virtiofs
  │     │     ├─ VirtioSocket                       ← VSOCK for persistent Session
  │     │     └─ VirtioConsole (serial)             ← boot diagnostics
  │     │
  │     ├─ vm.start()
  │     │
  │     │  ┌─────── Linux VM (arm64) ────────┐
  │     │  │  initrd init                    │
  │     │  │    ├─ mount virtiofs → /mnt/work│
  │     │  │    ├─ chroot /mnt/work          │
  │     │  │    └─ bash -c "<cmd>"           │
  │     │  │                                 │
  │     │  │  Result → .vz_stdout/.vz_stderr │
  │     │  └─────────────────────────────────┘
  │     │
  │     └─ Read result files → ExecutionResult
  │
  └─ ~840ms cold boot-to-result
```

### Windows

```
Windows host
  │
  ├─ Session::open() / run()
  │     │
  │     │  named pipe \\.\pipe\tokimo-sandbox-svc (OVERLAPPED)
  │     │
  │     ├─ tokimo-sandbox-svc.exe (NT AUTHORITY\SYSTEM)
  │     │     │
  │     │     ├─ alloc per-session vsock port + HvSocket service GUID
  │     │     ├─ register GUID in HKLM GuestCommunicationServices
  │     │     ├─ clone rootfs.vhdx → per-session copy
  │     │     ├─ bind AF_HYPERV listener (HV_GUID_WILDCARD, session GUID)
  │     │     │
  │     │     ├─ HcsCreateComputeSystem(schema)
  │     │     │     └─ LinuxKernelDirect(vmlinuz, initrd.img)
  │     │     │     └─ SCSI: per-session rootfs.vhdx
  │     │     │     └─ Plan9("work") → workspace via vsock 9p
  │     │     │     └─ HvSocket ServiceTable[session-guid]
  │     │     │
  │     │     ├─ HcsStartComputeSystem
  │     │     │
  │     │     │  ┌─────── Linux VM (amd64) ────────────────────┐
  │     │     │  │  initrd init.sh                             │
  │     │     │  │    ├─ modprobe hv_vmbus hv_sock …           │
  │     │     │  │    ├─ mount /dev/sda (ext4 rootfs)          │
  │     │     │  │    └─ chroot → exec tokimo-sandbox-init     │
  │     │     │  │                                             │
  │     │     │  │  tokimo-sandbox-init (PID 1)                │
  │     │     │  │    ├─ AF_VSOCK connect(CID=2, port=<sess>)  │
  │     │     │  │    ├─ mount Plan9 "work" → /mnt/work        │
  │     │     │  │    └─ Op::OpenShell / Spawn / Exec …        │
  │     │     │  └─────────────────────────────────────────────┘
  │     │     │
  │     │     ├─ accept hvsock → bridge pipe ↔ hvsock (tunnel)
  │     │     └─ reply SessionOpened → pipe tunnel active
  │     │
  │     └─ WinInitClient: Hello / OpenShell / Spawn / Exec over tunnel
  │
  └─ ~600ms cold boot-to-first-exec
```

**Shared across macOS and Windows:**
- Same kernel (`vmlinuz`), initrd (`init.sh` + busybox), rootfs (Debian 13)
- Same init script auto-detects virtiofs (macOS) vs 9p (Windows)
- Same result file convention: `.vz_stdout`, `.vz_stderr`, `.vz_exit_code`

## API

### One-shot execution

```rust
pub fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult>;

pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub oom_killed: bool,
}
```

### Persistent sessions (all platforms including Windows)

```rust
let mut sess = Session::open(&cfg)?;
sess.exec("export FOO=bar")?;
sess.exec("cd /tmp && touch hello")?;
let job = sess.spawn("sleep 5 && echo done")?;
let result = job.wait_with_timeout(Duration::from_secs(10))?;
let pty = sess.open_pty(24, 80, &["/bin/bash".into()], &[], None)?;
sess.close()?;
```

Windows sessions use the same API. PTY support on Windows is planned but not yet implemented.

### Configuration

```rust
SandboxConfig::new("/tmp/work")
    .name("agent-sandbox")
    .network(NetworkPolicy::Blocked)
    .limits(ResourceLimits { max_memory_mb: 512, timeout_secs: 60, .. })
    .mount(Mount::ro("/opt/cache"))
    .mount(Mount::rw("/host/output").guest("/out"))
    .env("LANG", "C.UTF-8")
    .cwd("/tmp");
```

### Network policies

| Policy | Network | Enforcement | Platform |
|---|---|---|---|
| `Blocked` | none | — | all |
| `AllowAll` | full host | — | all |
| `Observed { sink }` | full | advisory audit (L4+L7) | Linux |
| `Gated { sink, allow_hosts }` | full | deny non-matching hosts | Linux |

On Linux, `Observed` / `Gated` layer seccomp-notify (L4) + transparent HTTP(S) proxy (L7). See [`docs/network-observability.md`](./docs/network-observability.md).

## Examples

```bash
# Cross-platform one-shot
cargo run --example basic               # ls / id / hostname
cargo run --example rm_rf_test          # proves rm -rf / can't touch host
cargo run --example concurrent_oneshot  # parallel run() calls
cargo run --example edge_cases          # boundary inputs
cargo run --example torture_test        # stress test

# Linux-only (bwrap + seccomp)
cargo run --example shell               # interactive shell
cargo run --example session             # persistent Session
cargo run --example parallel_in_session # multiple jobs in one Session
cargo run --example kill_job            # JobHandle::kill / wait
cargo run --example pty_smoke           # PTY allocation + raw mode
cargo run --example init_smoke          # tokimo-sandbox-init protocol
cargo run --example gated_network       # network observability (Gated)
cargo run --example l4_observer         # L4 + L7 event pipeline

# Platform VM smoke tests
cargo run --example vz_smoke            # macOS Virtualization.framework
cargo run --example hv_smoke            # Windows Hyper-V SYSTEM service
```

## Tests

### Unit tests (all platforms)

```bash
cargo test --lib                           # 13 lib tests (Sandbox API + session_registry)
cargo test --bin tokimo-sandbox-svc --lib  # 34 svc tests (vmconfig, vhdx_pool, inflight, …)
```

### Windows integration tests

End-to-end tests (15 cases, ~42 s) live in [`tests/sandbox_integration.rs`](tests/sandbox_integration.rs) and exercise the **real** HCS-backed VM through `\\.\pipe\tokimo-sandbox-svc` — no mocks. Coverage: lifecycle, shell I/O, multi-shell streams + signals, plan9 share dynamics, network policy, multi-session concurrency.

**Hard requirements:**

| | |
|---|---|
| Administrator + Hyper-V enabled | HCS / HCN APIs are SYSTEM-only |
| **PowerShell 7** (`pwsh.exe`) | PS 5.1 mishandles `cargo`'s stderr-on-success |
| `vm/{vmlinuz,initrd.img,rootfs.vhdx}` | `pwsh scripts/fetch-vm.ps1` |

**Run:**

```powershell
# From an elevated pwsh 7 prompt — handles build + svc launch + test + cleanup.
pwsh scripts\test-integration.ps1
```

The wrapper builds, launches `tokimo-sandbox-svc.exe --console` in the background (logs → `target\integration\svc.log`), runs `cargo test --test sandbox_integration` (logs → `target\integration\test.log`), then kills the svc process.

If you already have the service running and an elevated terminal:

```powershell
cargo test --test sandbox_integration -- --nocapture
# Single test:
cargo test --test sandbox_integration multi_shell_isolated_streams -- --nocapture
```

See [`tests/README.md`](tests/README.md) for the full test inventory and debug-artefact paths.

### Linux & macOS integration

Linux (bwrap) and macOS (VZ) integration runners are not yet ported — see the TODO sections in [`tests/README.md`](tests/README.md). Only the Sandbox `--lib` / `--bin --lib` unit suites run cross-platform today.

## Init control protocol (v1, Linux)

The host communicates with `tokimo-sandbox-init` via length-prefixed JSON frames over `SOCK_SEQPACKET` (Linux) or VSOCK (macOS Session). PTY master fds via `SCM_RIGHTS`.

```jsonc
client → init  { "op": "Hello",      "protocol": 1 }
init   → client { "ok": true,         "init_pid": 1 }

client → init  { "op": "OpenShell",  "argv": ["/bin/bash","--noprofile","--norc"] }
init   → client { "ok": true,         "result": { "child_id": "c1", "pid": 12 } }

client → init  { "op": "Spawn",      "argv": ["/bin/bash","-c","echo hi"],
                 "stdio": "Pipes",    "inherit_from_child": "c1" }
init   → client { "ok": true,         "result": { "child_id": "c2", "pid": 14 } }

client → init  { "op": "Spawn",      "argv": ["/bin/bash","-l"],
                 "stdio": { "Pty": { "rows": 24, "cols": 80 } } }
init   → client { "ok": true,         "result": { "child_id": "c3", "pid": 15 } }
                  // + SCM_RIGHTS: PTY master fd

init   → client { "event": "Exit",   "child_id": "c2", "code": 0 }
```

## Why not Docker?

| | tokimo-package-sandbox | Docker |
|---|---|---|
| **Daemon** | library call (or SYSTEM service on Windows) | dockerd required |
| **Startup** | ~50ms (Linux) / ~840ms (macOS VZ) / ~600ms (Windows HCS) | ~1–3s |
| **Images** | none (reuses Debian rootfs) | required |
| **API** | Rust native | subprocess `docker run` |
| **Use case** | "run this one untrusted command" | "deploy this service stack" |

## Related

- [`packaging/vm-image/README.md`](packaging/vm-image/README.md) — how the
  in-repo Debian rootfs + kernel + initrd are built (two-layer CI cache:
  `vm-base.yml` slow rebuild, `vm-image.yml` fast init-binary rebake)

## License

MIT. See [LICENSE](./LICENSE).
