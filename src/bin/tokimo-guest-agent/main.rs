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
//! cargo build --release --bin tokimo-guest-agent --target x86_64-unknown-linux-musl
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
