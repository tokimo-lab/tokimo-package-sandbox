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
mod pty;
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

    // PTY port is offset +1 from the one-shot RPC port by convention.
    // One-shot default 1024 => PTY default 1025.
    // This allows separate vsock listeners for different protocol semantics:
    // - port: one request/response per connection (spawn_command)
    // - port+1: long-lived bidirectional PTY sessions
    let pty_port = port + 1;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    // Spawn one-shot RPC server
    let rpc_handle = rt.spawn(async move {
        if let Err(e) = server::run(port).await {
            eprintln!("tokimo-guest-agent RPC: fatal: {e:#}");
            std::process::exit(1);
        }
    });

    // Spawn PTY server
    let pty_handle = rt.spawn(async move {
        if let Err(e) = server::run_pty(pty_port).await {
            eprintln!("tokimo-guest-agent PTY: fatal: {e:#}");
            std::process::exit(1);
        }
    });

    // Wait for both servers
    rt.block_on(async {
        tokio::select! {
            _ = rpc_handle => {}
            _ = pty_handle => {}
        }
    });
}

/// Mount /proc, /sys, /dev, and /mnt (for virtiofs) inside the microVM guest.
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

    // Create and mount devpts so forkpty/openpty can allocate PTYs.
    if let Err(e) = std::fs::create_dir_all("/dev/pts") {
        eprintln!("tokimo-guest-agent: warning: create /dev/pts: {e}");
    }

    let ret = unsafe {
        libc::mount(
            b"devpts\0".as_ptr() as *const libc::c_char,
            b"/dev/pts\0".as_ptr() as *const libc::c_char,
            b"devpts\0".as_ptr() as *const libc::c_char,
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // EBUSY means already mounted — not an error in our context.
        if err.raw_os_error() != Some(libc::EBUSY) {
            eprintln!("tokimo-guest-agent: warning: mount /dev/pts (devpts): {err}");
        }
    }

    // Create and mount virtiofs share at /mnt
    if let Err(e) = std::fs::create_dir_all("/mnt") {
        eprintln!("tokimo-guest-agent: warning: create /mnt: {e}");
    }

    let ret = unsafe {
        libc::mount(
            b"tokimoshare\0".as_ptr() as *const libc::c_char,
            b"/mnt\0".as_ptr() as *const libc::c_char,
            b"virtiofs\0".as_ptr() as *const libc::c_char,
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // EBUSY means already mounted; ENODEV means virtiofs not available (no --fs flag)
        if err.raw_os_error() != Some(libc::EBUSY) && err.raw_os_error() != Some(libc::ENODEV) {
            eprintln!("tokimo-guest-agent: warning: mount /mnt (virtiofs): {err}");
        }
    }
}
