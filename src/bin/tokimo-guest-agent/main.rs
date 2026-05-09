//! `tokimo-guest-agent` — vsock RPC server running inside a microVM guest.
//!
//! Intended to run as PID 1 (or early init) inside a Cloud-Hypervisor
//! microVM.  Listens on virtio-vsock, accepts connections from the host,
//! executes commands, and streams output back as line-delimited JSON frames.
//!
//! # Environment
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `TOKIMO_GUEST_VSOCK_PORT` | `1024` | virtio-vsock port to listen on |
//!
//! # Protocol
//!
//! Line-delimited JSON: one request line in, N response lines out, then the
//! connection is closed.  See [`exec::Request`] / [`exec::Response`].
//!
//! # Static build (required for initrd packaging)
//!
//! ```bash
//! PATH="$HOME/zig-x86_64-linux-0.14.1:$PATH" cargo-zigbuild zigbuild \
//!     --release --bin tokimo-guest-agent --target x86_64-unknown-linux-musl
//! ```
//!
//! This target requires the `musl` toolchain; see `docs/platform/linux-sandbox-roadmap.md`.

#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod server;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tokimo-guest-agent: Linux-only binary");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    // When compiled as a static musl binary running as initrd PID 1, mount
    // essential pseudo-filesystems before starting the vsock listener.
    // Gated on target_env="musl" so unit tests (gnu target) are never affected.
    #[cfg(target_env = "musl")]
    mount_guest_fs();

    let port: u32 = std::env::var("TOKIMO_GUEST_VSOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    if let Err(e) = rt.block_on(server::run(port)) {
        eprintln!("tokimo-guest-agent: fatal: {e:#}");
        std::process::exit(1);
    }
}

/// Mount /proc, /sys, and /dev inside the microVM guest.
///
/// Called only when compiled as a musl static binary (initrd PID 1 scenario).
/// Failures are logged as warnings but never panic — the vsock listener is
/// started regardless so the host can still reach the agent.
#[cfg(all(target_os = "linux", target_env = "musl"))]
fn mount_guest_fs() {
    let entries: &[(&[u8], &[u8], &[u8])] = &[
        (b"proc\0", b"/proc\0", b"proc\0"),
        (b"sysfs\0", b"/sys\0", b"sysfs\0"),
        (b"devtmpfs\0", b"/dev\0", b"devtmpfs\0"),
    ];
    for (src, target, fstype) in entries {
        let ret = unsafe {
            libc::mount(
                src.as_ptr() as *const libc::c_char,
                target.as_ptr() as *const libc::c_char,
                fstype.as_ptr() as *const libc::c_char,
                0,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // EBUSY means already mounted — not an error in our context.
            if err.raw_os_error() != Some(libc::EBUSY) {
                let path = std::str::from_utf8(target).unwrap_or("?").trim_end_matches('\0');
                eprintln!("tokimo-guest-agent: warning: mount {path}: {err}");
            }
        }
    }
}
