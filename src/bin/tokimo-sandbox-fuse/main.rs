//! `tokimo-sandbox-fuse` — guest-side FUSE → host VfsBackend bridge.
//!
//! Linux-only. Runs inside the sandbox container/VM. One process per
//! mount: `init` spawns this binary with the per-session vsock port,
//! the logical mount name, and the in-guest mountpoint. The process
//! opens an `AF_VSOCK` connection to the host, performs the
//! [`Frame::Hello`] handshake (binding to `mount_name`), then mounts a
//! FUSE filesystem at the target path and translates kernel FUSE ops
//! into wire [`Req`]s.
//!
//! ```text
//!   kernel FUSE  ──fuser callbacks──▶  worker thread  ──postcard──▶  host
//!   /<target>                                                       FuseHost
//! ```
//!
//! ## CLI
//!
//! ```text
//! tokimo-sandbox-fuse \
//!     --transport vsock --port 2223 \
//!     --mount-name work \
//!     --target /mnt/work \
//!     [--read-only] \
//!     [--allow-other]
//! ```
//!
//! Or for tests / Linux bwrap:
//!
//! ```text
//! tokimo-sandbox-fuse --transport unix-fd --fd 4 --mount-name … --target …
//! ```
//!
//! Exit codes: 0 normal unmount, non-zero on protocol or mount error.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tokimo-sandbox-fuse only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}
