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
| **Windows** | WSL2 + bubblewrap | strong — VM + Linux sandbox |

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
| **macOS** | Linux kernel + initrd from [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) |
| **Windows** | `wsl --install`, then `sudo apt install bubblewrap` |

## macOS setup

The macOS backend boots a lightweight Linux VM via Virtualization.framework (macOS 11+). You need a kernel and initrd:

```bash
# 1. Download rootfs + kernel from tokimo-package-rootfs releases
#    (or build from source: git clone tokimo-package-rootfs && bash build.sh arm64)

# 2. Install artifacts to default locations
mkdir -p ~/.tokimo ~/.tokimo/kernel
# kernel → ~/.tokimo/kernel/vmlinuz
# initrd → ~/.tokimo/initrd.img
# rootfs → ~/.tokimo/rootfs/    (or set TOKIMO_VZ_ROOTFS)

# 3. Sign the binary with virtualization entitlement
codesign --entitlements vz.entitlements --force -s - target/debug/your-app

# 4. Run
TOKIMO_VZ_ROOTFS=/path/to/rootfs ./your-app
```

Entitlement file (`vz.entitlements`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.virtualization</key><true/>
</dict></plist>
```

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
  │     │  │    └─ bash -c "<decoded_cmd>"   │
  │     │  │                                 │
  │     │  │  Result written to:             │
  │     │  │    /mnt/work/.vz_stdout         │
  │     │  │    /mnt/work/.vz_stderr         │
  │     │  │    /mnt/work/.vz_exit_code      │
  │     │  └─────────────────────────────────┘
  │     │
  │     └─ Read result files → ExecutionResult
  │
  └─ ~840ms cold boot-to-result
```

### Windows

Windows delegates to WSL2, which provides a full Linux kernel with namespace + seccomp isolation. The host-side `windows.rs` is a thin forwarding layer: it translates Windows paths to `/mnt/` WSL paths, assembles a `bwrap` command line, and executes it via `wsl -e bash -lc '...'`.

```
Windows host
  │
  ├─ run()  ──► wsl -e bash -lc 'bwrap --unshare-all ... -- <cmd>'
  │               │
  │               └──► WSL2 VM
  │                      │
  │                      ├─ bwrap namespaces (user, mount, PID, net, IPC, UTS)
  │                      ├─ seccomp BPF (~300 syscalls)
  │                      ├─ work_dir bind-mounted at /tmp
  │                      └─ command runs fully isolated inside the VM
  │
  └─ Session::open()  ──► wsl -e bash -lc 'bwrap ... -- /bin/bash --noprofile --norc'
                            │
                            └──► bash REPL over stdio (sentinel protocol)
                                  ├─ exec / spawn  ──► same semantics as Linux
                                  └─ no init control socket; bash sentinel carries
                                     cwd/env inheritance and I/O framing
```

- **Requires WSL2** — `wsl --install` once, then `sudo apt install bubblewrap` inside the WSL distro
- **Same Linux sandbox** — reuses `bwrap`, seccomp BPF, and cgroups inside the VM verbatim
- **Path translation** — `C:\Users\...` → `/mnt/c/Users/...` for bind mounts and CWD
- **No console window** — `CREATE_NO_WINDOW` flag suppresses the WSL terminal popup
- **Network observe unsupported** — `Observed` / `Gated` return an error on Windows; use Linux directly for those policies
- **Fallback mode** — set `SAFEBOX_WSL_NO_BWRAP=1` to skip bwrap inside WSL (WSL-only isolation, no filesystem sandbox)

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
let pty = sess.open_pty(24, 80, &["/bin/bash".into()], &[], None)?;  // Linux
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
cargo run --example gated_network     # Network observability (Linux)
cargo run --example l4_observer       # L4+L7 event pipeline (Linux)
```

## Init control protocol (v1, Linux)

The host communicates with `tokimo-sandbox-init` via length-prefixed JSON frames over `SOCK_SEQPACKET` (Linux) or VSOCK (future macOS Session). PTY master fds via `SCM_RIGHTS`.

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
| **Daemon** | none (library call) | dockerd required |
| **Startup** | ~50ms (Linux) / ~840ms (macOS VZ) | ~1–3s |
| **Images** | none (reuses host /usr, /bin, /lib) | required |
| **API** | Rust native | subprocess `docker run` |
| **Use case** | "run this one untrusted command" | "deploy this service stack" |

## Related

- [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) — Debian rootfs images (amd64 + arm64)

## License

MIT. See [LICENSE](./LICENSE).
