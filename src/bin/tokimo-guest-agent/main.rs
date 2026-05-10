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

    bring_up_guest_network();
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
fn bring_up_guest_network() {
    if !std::path::Path::new("/sys/class/net/eth0").exists() {
        return;
    }

    log_guest_command_result(
        "ip link set lo up",
        guest_applet_command("ip", &["link", "set", "lo", "up"]).output(),
    );
    log_guest_command_result(
        "ip link set eth0 up",
        guest_applet_command("ip", &["link", "set", "eth0", "up"]).output(),
    );
    let udhcpc_script = "/etc/udhcpc/default.script";
    let mut udhcpc_args = vec!["-i", "eth0", "-q", "-n", "-t", "5"];
    let udhcpc_command = if std::path::Path::new(udhcpc_script).exists() {
        udhcpc_args.extend_from_slice(&["-s", udhcpc_script]);
        "udhcpc -i eth0 -q -n -t 5 -s /etc/udhcpc/default.script"
    } else {
        "udhcpc -i eth0 -q -n -t 5"
    };
    log_guest_command_result(udhcpc_command, guest_applet_command("udhcpc", &udhcpc_args).output());
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
fn guest_applet_command(applet: &str, args: &[&str]) -> std::process::Command {
    let path = match applet {
        "ip" => first_existing_path(&["/bin/ip", "/sbin/ip", "/usr/bin/ip", "/usr/sbin/ip"]),
        "udhcpc" => first_existing_path(&["/sbin/udhcpc", "/bin/udhcpc", "/usr/sbin/udhcpc", "/usr/bin/udhcpc"]),
        _ => None,
    };

    let mut command = if let Some(path) = path {
        std::process::Command::new(path)
    } else if std::path::Path::new("/bin/busybox").exists() {
        let mut command = std::process::Command::new("/bin/busybox");
        command.arg(applet);
        command
    } else {
        std::process::Command::new(applet)
    };
    command.args(args).env("PATH", "/sbin:/bin:/usr/sbin:/usr/bin");
    command
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
fn first_existing_path(paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|path| std::path::Path::new(path).exists())
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
fn log_guest_command_result(command: &str, output: std::io::Result<std::process::Output>) {
    match output {
        Ok(output) => {
            if output.status.success() {
                eprintln!("tokimo-guest-agent: network: {command}: success ({})", output.status);
            } else {
                eprintln!(
                    "tokimo-guest-agent: warning: network: {command}: failed ({})",
                    output.status
                );
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stdout = stdout.trim();
            if !stdout.is_empty() {
                eprintln!("tokimo-guest-agent: network: {command}: stdout: {stdout}");
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            if !stderr.is_empty() {
                eprintln!("tokimo-guest-agent: network: {command}: stderr: {stderr}");
            }
        }
        Err(e) => {
            eprintln!("tokimo-guest-agent: warning: network: {command}: spawn failed: {e}");
        }
    }
}
