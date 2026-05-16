//! Cloud Hypervisor VM bootstrap (parallel to `src/macos/vm.rs`).
//!
//! Boots a Linux micro-VM whose PID 1 is `tokimo-sandbox-init`, mounts the
//! rootfs as a virtiofs share with tag `work` (the init binary picks this
//! up and `chroot`s into it), and exchanges four logical channels with
//! the host over Cloud Hypervisor's hybrid-vsock transport:
//!
//! * **init**       (vsock port 2222) — control protocol
//! * **netstack**   (vsock port 4444) — guest's `tokimo-tun-pump`
//! * **fuse**       (vsock port 5555) — one connection per FUSE mount
//! * **host_exec**  (vsock port 5556) — `tokimo-host-exec` bridge
//!
//! All four channels are guest-initiated (`tokimo.guest_listens=0` in the
//! cmdline). Cloud Hypervisor exposes a control UDS at `<socket>`; when
//! the guest connects out to host CID 2 / port P, CH opens a connection
//! to a sidecar UDS at `<socket>_<P>` that the host must already be
//! listening on. We pre-bind all four sidecar listeners *before* spawning
//! cloud-hypervisor.
//!
//! The rootfs is shared via an out-of-process `virtiofsd` (sandboxed to a
//! mount namespace because pivot_root is blocked under Docker seccomp).
//! Networking is handled by the host-side smoltcp gateway (see
//! `src/netstack/`); cloud-hypervisor is started **without** a virtio-net
//! device.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::api::NetworkPolicy;
use crate::error::{Error, Result};

/// Vsock port the guest's `tokimo-sandbox-init` listens on.
pub const INIT_VSOCK_PORT: u32 = 2222;

/// Vsock port for guest's `tokimo-tun-pump` netstack data channel.
pub const NETSTACK_VSOCK_PORT: u32 = 4444;

/// Vsock port for guest-initiated FUSE-over-vsock connections.
pub const FUSE_VSOCK_PORT: u32 = 5555;

/// Vsock port for guest-initiated host-exec bridge connections.
pub const HOST_EXEC_VSOCK_PORT: u32 = 5556;

/// Tag used for the rootfs virtiofs share. Must match the value
/// `tokimo-sandbox-init/init.sh` looks for.
const ROOTFS_TAG: &str = "work";

/// Per-process CID allocator. Cloud Hypervisor requires `cid >= 3`.
fn alloc_cid() -> u32 {
    static NEXT_CID: AtomicU32 = AtomicU32::new(100);
    NEXT_CID.fetch_add(1, Ordering::Relaxed)
}

/// VM bootstrap parameters derived from `ConfigureParams`.
#[derive(Debug, Clone)]
pub struct ChVmConfig {
    pub memory_mb: u64,
    pub cpu_count: u32,
    pub network: NetworkPolicy,
    pub base_rootfs: PathBuf,
    pub vm_dir: PathBuf,
}

/// Result of `boot_ch_vm`: a started cloud-hypervisor + virtiofsd pair,
/// plus four `UnixListener`s ready to accept guest-initiated connections
/// on the corresponding sidecar UDS files.
pub struct BootedChVm {
    pub vm: ChVm,
    pub init_listener: UnixListener,
    pub netstack_listener: UnixListener,
    pub fuse_listener: UnixListener,
    pub host_exec_listener: UnixListener,
}

/// Owns the cloud-hypervisor and virtiofsd child processes and all of
/// their on-disk artifacts. Dropping reaps both children and removes the
/// UDS files.
pub struct ChVm {
    pub cid: u32,
    pub vsock_uds: PathBuf,
    pub api_socket: PathBuf,
    pub virtiofsd_socket: PathBuf,
    /// Short-path scratch dir (under /tmp) that holds the UDS files; kept
    /// separate from `vm_dir` so socket paths stay well below SUN_LEN even
    /// when the caller's `vm_dir` is deep (e.g. GitHub Actions runners
    /// have `cwd` ~60 chars, which would push `<vm_dir>/ch-vsock-XXX.sock_NNNN`
    /// past 108 bytes).
    sock_dir: PathBuf,
    ch_child: Option<Child>,
    virtiofsd_child: Option<Child>,
}

impl Drop for ChVm {
    fn drop(&mut self) {
        // Kill cloud-hypervisor first (releases vsock + virtiofs clients),
        // then virtiofsd, then clean up files.
        if let Some(mut c) = self.ch_child.take() {
            kill_and_wait(&mut c, "cloud-hypervisor", Duration::from_secs(5));
        }
        if let Some(mut c) = self.virtiofsd_child.take() {
            kill_and_wait(&mut c, "virtiofsd", Duration::from_secs(3));
        }
        for p in [
            self.api_socket.clone(),
            self.virtiofsd_socket.clone(),
            self.vsock_uds.clone(),
            sidecar_path(&self.vsock_uds, INIT_VSOCK_PORT),
            sidecar_path(&self.vsock_uds, NETSTACK_VSOCK_PORT),
            sidecar_path(&self.vsock_uds, FUSE_VSOCK_PORT),
            sidecar_path(&self.vsock_uds, HOST_EXEC_VSOCK_PORT),
        ] {
            let _ = std::fs::remove_file(p);
        }
        // Best-effort: remove the short-path scratch dir once empty.
        let _ = std::fs::remove_dir(&self.sock_dir);
    }
}

fn kill_and_wait(child: &mut Child, name: &str, timeout: Duration) {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                tracing::warn!("{name}: try_wait failed: {e}");
                return;
            }
        }
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

/// Compute the sidecar UDS path Cloud Hypervisor uses for guest-initiated
/// connections to vsock port `port`. The convention is `<socket>_<port>`.
pub fn sidecar_path(vsock_uds: &Path, port: u32) -> PathBuf {
    let mut s = vsock_uds.as_os_str().to_owned();
    s.push(format!("_{port}"));
    PathBuf::from(s)
}

/// Resolve the path to the bundled cloud-hypervisor binary.
pub fn cloud_hypervisor_binary() -> Result<PathBuf> {
    locate_binary("bin/cloud-hypervisor/current/bin/cloud-hypervisor", "cloud-hypervisor")
}

/// Resolve the path to the bundled virtiofsd binary.
pub fn virtiofsd_binary() -> Result<PathBuf> {
    locate_binary("bin/virtiofsd/current/virtiofsd", "virtiofsd")
}

/// Resolve the ch kernel path. Linux ch backend uses the same Debian
/// generic `vmlinuz` bzImage that ships in the `vm-kernel-*` release —
/// cloud-hypervisor v36+ accepts bzImage, and the initrd loads
/// `vmw_vsock_virtio_transport` early so the host↔init vsock handshake
/// works without a custom PVH ELF.
pub fn ch_vmlinux_path(base_rootfs: &Path) -> Result<PathBuf> {
    let kernel = base_rootfs.join("vmlinuz");
    if !kernel.exists() {
        return Err(Error::other(format!(
            "kernel not found at {} (run scripts/linux/fetch-vm.sh)",
            kernel.display()
        )));
    }
    Ok(kernel)
}

fn locate_binary(relative: &str, what: &str) -> Result<PathBuf> {
    // 1) Relative to the current working directory (cargo test).
    let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cand = here.join(relative);
    if cand.exists() {
        return Ok(cand);
    }
    // 2) Walk up from the executable's directory.
    if let Ok(exe) = std::env::current_exe() {
        let mut cur: Option<&Path> = exe.parent();
        while let Some(d) = cur {
            let c = d.join(relative);
            if c.exists() {
                return Ok(c);
            }
            cur = d.parent();
        }
    }
    Err(Error::other(format!(
        "could not locate bundled {what} (expected at {relative} relative to repo root)"
    )))
}

/// Boot a fresh cloud-hypervisor VM. The returned `BootedChVm` is ready
/// for the caller to `.accept()` the four sidecar UDS listeners.
pub fn boot_ch_vm(config: &ChVmConfig) -> Result<BootedChVm> {
    // Set up rootfs (the writable per-session copy that virtiofsd shares).
    crate::rootfs_init::ensure_rootfs(&config.base_rootfs, &config.vm_dir)?;
    let kernel = ch_vmlinux_path(&config.base_rootfs)?;
    let initrd = config.base_rootfs.join("initrd.img");
    let rootfs_dir = config.vm_dir.join("rootfs");

    if !initrd.exists() {
        return Err(Error::other(format!("initrd missing at {}", initrd.display())));
    }
    if !rootfs_dir.is_dir() {
        return Err(Error::other(format!("rootfs missing at {}", rootfs_dir.display())));
    }

    let cid = alloc_cid();

    // Place all UDS files under a short-path scratch dir so that
    // `<dir>/ch-vsock-<cid>.sock_<port>` stays well under SUN_LEN (108).
    // The caller's `vm_dir` may live deep under a long cwd (GitHub
    // Actions runners use ~60-char cwds, which would overflow).
    let sock_dir = std::env::temp_dir().join(format!("tk-ch-{cid}"));
    std::fs::create_dir_all(&sock_dir)
        .map_err(|e| Error::other(format!("create sock dir {}: {e}", sock_dir.display())))?;

    // Unique socket paths per VM (one cloud-hypervisor instance per ChVm).
    let vsock_uds = sock_dir.join(format!("v{cid}.sock"));
    let api_socket = sock_dir.join(format!("a{cid}.sock"));
    let virtiofsd_socket = sock_dir.join(format!("f{cid}.sock"));

    // Remove any stale files from a previous crashed run before binding.
    for p in [&vsock_uds, &api_socket, &virtiofsd_socket] {
        let _ = std::fs::remove_file(p);
    }

    // Pre-bind sidecar UDS listeners for the four guest-initiated channels.
    // Cloud Hypervisor refuses to deliver guest connections if these don't
    // already exist when the guest calls `connect()`.
    let init_listener = bind_sidecar(&vsock_uds, INIT_VSOCK_PORT)?;
    let netstack_listener = bind_sidecar(&vsock_uds, NETSTACK_VSOCK_PORT)?;
    let fuse_listener = bind_sidecar(&vsock_uds, FUSE_VSOCK_PORT)?;
    let host_exec_listener = bind_sidecar(&vsock_uds, HOST_EXEC_VSOCK_PORT)?;

    // Spawn virtiofsd, wait for its socket to appear.
    let virtiofsd_child = spawn_virtiofsd(&virtiofsd_socket, &rootfs_dir)?;
    wait_for_path(&virtiofsd_socket, Duration::from_secs(5)).map_err(|e| {
        Error::other(format!(
            "virtiofsd socket {} did not appear: {e}",
            virtiofsd_socket.display()
        ))
    })?;

    // Build the kernel cmdline. All four channels are guest-initiated.
    let dns_flag = match config.network {
        NetworkPolicy::AllowAll => "tokimo.netdns=on",
        NetworkPolicy::Blocked => "tokimo.netdns=off",
    };
    let cmdline = format!(
        "console=hvc0 earlyprintk=hvc0 \
         tokimo.session=1 tokimo.init_port={INIT_VSOCK_PORT} tokimo.guest_listens=0 \
         tokimo.net=netstack tokimo.netstack_port={NETSTACK_VSOCK_PORT} {dns_flag} \
         tokimo.host_exec_port={HOST_EXEC_VSOCK_PORT} \
         net.ifnames=0 biosdevname=0 \
         PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
         HOME=/root TERM=xterm-256color LANG=C.UTF-8"
    );

    // 0 = no limit → pick something sane for cloud-hypervisor.
    let memory_mb = if config.memory_mb == 0 { 4096 } else { config.memory_mb };
    let cpu_count = if config.cpu_count == 0 { 4 } else { config.cpu_count };

    let ch_bin = cloud_hypervisor_binary()?;
    let mut cmd = Command::new(&ch_bin);
    cmd.arg("--api-socket")
        .arg(format!("path={}", api_socket.display()))
        .arg("--kernel")
        .arg(&kernel)
        .arg("--initramfs")
        .arg(&initrd)
        .arg("--cmdline")
        .arg(&cmdline)
        .arg("--cpus")
        .arg(format!("boot={cpu_count}"))
        .arg("--memory")
        .arg(format!("size={memory_mb}M,shared=on"))
        .arg("--fs")
        .arg(format!(
            "tag={ROOTFS_TAG},socket={},num_queues=1,queue_size=512",
            virtiofsd_socket.display()
        ))
        .arg("--vsock")
        .arg(format!("cid={cid},socket={}", vsock_uds.display()))
        .arg("--console")
        .arg("off")
        .arg("--serial")
        .arg("off");

    // Inherit stdio for log visibility under cargo test.
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

    tracing::info!(
        kernel = %kernel.display(),
        initrd = %initrd.display(),
        rootfs = %rootfs_dir.display(),
        cid = cid,
        vsock = %vsock_uds.display(),
        "starting cloud-hypervisor VM"
    );

    let mut ch_child = cmd
        .spawn()
        .map_err(|e| Error::other(format!("spawn cloud-hypervisor ({}): {e}", ch_bin.display())))?;

    spawn_log_drain(&mut ch_child, "ch", cid);

    let vm = ChVm {
        cid,
        vsock_uds: vsock_uds.clone(),
        api_socket,
        virtiofsd_socket,
        sock_dir,
        ch_child: Some(ch_child),
        virtiofsd_child: Some(virtiofsd_child),
    };

    Ok(BootedChVm {
        vm,
        init_listener,
        netstack_listener,
        fuse_listener,
        host_exec_listener,
    })
}

fn bind_sidecar(vsock_uds: &Path, port: u32) -> Result<UnixListener> {
    let path = sidecar_path(vsock_uds, port);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .map_err(|e| Error::other(format!("bind sidecar UDS {} for port {port}: {e}", path.display())))?;
    Ok(listener)
}

fn spawn_virtiofsd(socket: &Path, shared_dir: &Path) -> Result<Child> {
    let bin = virtiofsd_binary()?;
    // `namespace` sandbox: virtiofsd unshares into a mount namespace and
    // binds the share dir inside it. The default `chroot` sandbox uses
    // pivot_root, which Docker's default seccomp policy denies — that is
    // *exactly* the environment our integration tests run under.
    let mut cmd = Command::new(&bin);
    cmd.arg("--socket-path")
        .arg(socket)
        .arg("--shared-dir")
        .arg(shared_dir)
        .arg("--cache")
        .arg("auto")
        .arg("--sandbox")
        .arg("namespace")
        .arg("--xattr")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    static LOG_ONCE: OnceLock<()> = OnceLock::new();
    LOG_ONCE.get_or_init(|| {
        tracing::info!("virtiofsd binary: {}", bin.display());
    });
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::other(format!("spawn virtiofsd ({}): {e}", bin.display())))?;
    spawn_log_drain(&mut child, "virtiofsd", 0);
    Ok(child)
}

fn wait_for_path(path: &Path, timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("path {} did not appear within {timeout:?}", path.display()),
    ))
}

/// Drain a child's stdout/stderr into the host's stderr with a tagged
/// prefix. Useful for debugging boot failures under cargo test.
fn spawn_log_drain(child: &mut Child, tag: &'static str, cid: u32) {
    use std::io::{BufRead, BufReader};
    if let Some(out) = child.stdout.take() {
        let tag_owned = format!("{tag}:{cid}");
        thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(|l| l.ok()) {
                eprintln!("[{tag_owned}] {line}");
            }
        });
    }
    if let Some(err) = child.stderr.take() {
        let tag_owned = format!("{tag}:{cid}");
        thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(|l| l.ok()) {
                eprintln!("[{tag_owned}] {line}");
            }
        });
    }
}
