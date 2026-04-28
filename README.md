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
| **macOS** | Linux kernel + initrd + rootfs from [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) |
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

Artifacts are built by [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) — a single CI pipeline produces kernel + initrd + rootfs for both macOS and Windows.

## macOS setup

The macOS backend boots a lightweight Linux VM via Virtualization.framework (macOS 11+).

```bash
# 1. Download artifacts
curl -LO https://github.com/tokimo-lab/tokimo-package-rootfs/releases/latest/download/tokimo-os-arm64.tar.zst
curl -LO https://github.com/tokimo-lab/tokimo-package-rootfs/releases/latest/download/rootfs-arm64.tar.zst

# 2. Extract to ~/.tokimo/
zstd -d tokimo-os-arm64.tar.zst && tar -xpf tokimo-os-arm64.tar -C ~/.tokimo/
mkdir -p ~/.tokimo/rootfs
zstd -d rootfs-arm64.tar.zst && tar -xpf rootfs-arm64.tar -C ~/.tokimo/rootfs/

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

The Windows backend uses a **SYSTEM-level service** (`tokimo-sandbox-svc.exe`) that creates Hyper-V VMs on behalf of non-admin users. Same architecture as Docker Desktop and Claude Desktop.

### 1. Enable Virtual Machine Platform

Open **Windows Features** → check **Virtual Machine Platform** → restart.

### 2. Install artifacts

```powershell
# Download
curl -LO https://github.com/tokimo-lab/tokimo-package-rootfs/releases/latest/download/tokimo-os-amd64.tar.zst
curl -LO https://github.com/tokimo-lab/tokimo-package-rootfs/releases/latest/download/rootfs-amd64.tar.zst

# Extract
zstd -d tokimo-os-amd64.tar.zst; tar -xpf tokimo-os-amd64.tar -C $env:USERPROFILE\.tokimo\
mkdir -p $env:USERPROFILE\.tokimo\rootfs
zstd -d rootfs-amd64.tar.zst; tar -xpf rootfs-amd64.tar -C $env:USERPROFILE\.tokimo\rootfs\
```

Expected layout:
```
~\.tokimo\
  kernel\vmlinuz      ← Linux kernel
  initrd.img          ← initramfs
  rootfs\             ← Debian 13 filesystem
```

### 3. First run

```rust
// On first call, the library auto-installs the service via UAC.
// User clicks "Yes" once. After that, everything is transparent.
let out = tokimo_package_sandbox::run(&["python3", "--version"], &cfg)?;
```

Custom paths via env vars: `TOKIMO_KERNEL`, `TOKIMO_INITRD`, `TOKIMO_ROOTFS`, `TOKIMO_MEMORY`, `TOKIMO_CPUS`.

### Distribution

When shipping an application that uses this library, bundle `tokimo-sandbox-svc.exe` alongside your binary:

```
your-app\
  your-app.exe
  tokimo-sandbox-svc.exe   ← copy from cargo build output
```

The library finds the service binary next to the process executable and auto-installs it on first use.

### Debugging

```powershell
# Terminal 1: run service in foreground (see all logs)
cargo build --bin tokimo-sandbox-svc
.\target\debug\tokimo-sandbox-svc.exe --console

# Terminal 2: run examples
cargo run --example hv_smoke
```

In console mode, no UAC or service installation is needed — the library auto-detects the pipe and connects directly.

To uninstall: `.\tokimo-sandbox-svc.exe --uninstall` (needs admin).

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
  │     │     ├─ VirtioSocket                       ← VSOCK (future Session)
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
  ├─ run() → resolve paths → svc::client::exec_vm()
  │     │
  │     │  named pipe \\.\pipe\tokimo-sandbox-svc
  │     │
  │     ├─ tokimo-sandbox-svc.exe (NT AUTHORITY\SYSTEM)
  │     │     │
  │     │     ├─ HcsCreateComputeSystem(schema)
  │     │     │     └─ LinuxKernel(kernel, initrd)
  │     │     │     └─ Plan9("work") → rootfs shared via 9p
  │     │     │
  │     │     ├─ HcsStartComputeSystem
  │     │     │
  │     │     │  ┌─────── Linux VM (amd64) ──────┐
  │     │     │  │  initrd init                  │
  │     │     │  │    ├─ mount 9p → /mnt/work    │
  │     │     │  │    ├─ chroot /mnt/work        │
  │     │     │  │    └─ bash -c "<cmd>"         │
  │     │     │  │                               │
  │     │     │  │  Result → .vz_stdout/.vz_stderr│
  │     │     │  └───────────────────────────────┘
  │     │     │
  │     │     └─ Send response over pipe
  │     │
  │     └─ Parse response → ExecutionResult
  │
  └─ Service auto-installs via UAC on first use
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

### Persistent sessions (Linux only)

```rust
let mut sess = Session::open(&cfg)?;
sess.exec("export FOO=bar")?;
sess.exec("cd /tmp && touch hello")?;
let job = sess.spawn("sleep 5 && echo done")?;
let result = job.wait_with_timeout(Duration::from_secs(10))?;
let pty = sess.open_pty(24, 80, &["/bin/bash".into()], &[], None)?;
sess.close()?;
```

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
cargo run --example basic             # One-shot: ls, id, hostname
cargo run --example shell             # Interactive shell (Linux bwrap)
cargo run --example rm_rf_test        # Proves rm -rf / can't touch host
cargo run --example session           # Persistent session (Linux)
cargo run --example vz_smoke          # macOS VZ toolchain smoke test
cargo run --example hv_smoke          # Windows Hyper-V service smoke test
cargo run --example gated_network     # Network observability (Linux)
cargo run --example l4_observer       # L4+L7 event pipeline (Linux)
```

## Init control protocol (v1, Linux)

The host communicates with `tokimo-sandbox-init` via length-prefixed JSON frames over `SOCK_SEQPACKET` (Linux) or VSOCK (future). PTY master fds via `SCM_RIGHTS`.

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

- [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) — TokimoOS bundle (kernel + initrd + Debian rootfs)

## License

MIT. See [LICENSE](./LICENSE).
