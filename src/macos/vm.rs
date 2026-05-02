//! macOS VM bootstrap via `arcbox-vz` (Apple Virtualization.framework).
//!
//! Boots a Linux micro-VM whose PID 1 is `tokimo-sandbox-init`, mounts the
//! rootfs as a virtiofs share with tag `work` (the init binary picks this up
//! and `chroot`s into it), and connects to the guest's vsock listener on
//! port 1.

use std::env;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, SerialPortConfiguration, SharedDirectory,
    SingleDirectoryShare, SocketDeviceConfiguration, VirtioFileSystemDeviceConfiguration, VirtioSocketListener,
    VirtualMachine, VirtualMachineConfiguration, VirtualMachineState, is_supported,
};
use tokio::runtime::Runtime;

use crate::api::{Mount, NetworkPolicy};
use crate::error::{Error, Result};

/// Vsock port the guest's `tokimo-sandbox-init` listens on.
pub(crate) const INIT_VSOCK_PORT: u32 = 2222;

/// Vsock port the host listens on for the guest's `tokimo-tun-pump`
/// netstack data channel (NetworkPolicy::AllowAll only).
pub(crate) const NETSTACK_VSOCK_PORT: u32 = 4444;

/// Tag used for the rootfs virtiofs share. Must match the hard-coded value
/// in `tokimo-sandbox-init/main.rs` which mounts `work` at `/mnt/work`.
const ROOTFS_TAG: &str = "work";

/// Tag used for the per-session "dynamic share" pool — a single empty
/// directory that we APFS-clone into to add Plan9 shares at runtime.
pub(crate) const DYN_SHARE_TAG: &str = "tokimo_dyn";
/// Mount point inside the guest for the dynamic share pool.
pub(crate) const DYN_SHARE_GUEST_PATH: &str = "/__tokimo_dyn";

/// Result of `boot_vm`: a started `VirtualMachine`, the connected vsock fd
/// to the guest's init listener, and the tokio runtime that ran (and must
/// continue to drive) the async VZ APIs.
pub struct BootedVm {
    pub vm: VirtualMachine,
    pub vsock: OwnedFd,
    /// Listener for the guest-initiated netstack connection. Present iff
    /// `NetworkPolicy::AllowAll`. Caller is expected to `.accept()` once
    /// after the init handshake completes.
    pub netstack_listener: Option<VirtioSocketListener>,
    pub runtime: Arc<Runtime>,
}

/// VM bootstrap parameters derived from `ConfigureParams`.
#[derive(Debug, Clone)]
pub struct VmConfig {
    pub memory_mb: u64,
    pub cpu_count: u32,
    pub mounts: Vec<Mount>,
    pub network: NetworkPolicy,
    /// Host-side directory mounted as the dynamic-share pool.
    pub dyn_root: PathBuf,
}

/// Locate the VM artifacts: vmlinuz (file), initrd.img (file), rootfs/ (dir).
///
/// Priority:
/// 1. `TOKIMO_VM_DIR` env var.
/// 2. `<repo>/vm/` walking up from `current_exe()` and `current_dir()`.
/// 3. `~/.tokimo/`.
pub fn find_vm_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("TOKIMO_VM_DIR") {
        let p = PathBuf::from(dir);
        if validate_vm_dir(&p) {
            return Ok(p);
        }
        return Err(Error::other(format!(
            "TOKIMO_VM_DIR={} does not contain vmlinuz, initrd.img and a rootfs/ directory",
            p.display()
        )));
    }

    if let Ok(exe) = env::current_exe() {
        let mut cur: &Path = exe.as_path();
        for _ in 0..8 {
            if let Some(parent) = cur.parent() {
                let vm_dir = parent.join("vm");
                if validate_vm_dir(&vm_dir) {
                    return Ok(vm_dir);
                }
                cur = parent;
            } else {
                break;
            }
        }
    }

    if let Ok(cwd) = env::current_dir() {
        let mut cur: &Path = cwd.as_path();
        for _ in 0..8 {
            let vm_dir = cur.join("vm");
            if validate_vm_dir(&vm_dir) {
                return Ok(vm_dir);
            }
            if let Some(parent) = cur.parent() {
                cur = parent;
            } else {
                break;
            }
        }
    }

    if let Some(home) = env::var_os("HOME") {
        let p = PathBuf::from(home).join(".tokimo");
        if validate_vm_dir(&p) {
            return Ok(p);
        }
    }

    Err(Error::other(
        "VM artifacts not found. Set TOKIMO_VM_DIR, or place vmlinuz + initrd.img + rootfs/ in <repo>/vm/ or ~/.tokimo/.",
    ))
}

fn validate_vm_dir(dir: &Path) -> bool {
    dir.join("vmlinuz").is_file() && dir.join("initrd.img").is_file() && dir.join("rootfs").is_dir()
}

/// Boot the VM and connect to the guest's vsock listener.
pub fn boot_vm(config: &VmConfig) -> Result<BootedVm> {
    if !is_supported() {
        return Err(Error::other(
            "Virtualization.framework not available (requires macOS 11+)",
        ));
    }

    // Apple's Virtualization.framework dispatches VM lifecycle calls onto a
    // shared internal queue; building+starting two VMs in parallel inside
    // one process surfaces as "Start operation cancelled". Serialize the
    // build+start path so the dispatch queue sees one VM-start at a time.
    static BOOT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = BOOT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let vm_dir = find_vm_dir()?;
    let kernel = vm_dir.join("vmlinuz");
    let initrd = vm_dir.join("initrd.img");
    let rootfs = vm_dir.join("rootfs");

    let kernel_s = kernel.to_string_lossy().into_owned();
    let initrd_s = initrd.to_string_lossy().into_owned();
    let rootfs_s = rootfs.to_string_lossy().into_owned();
    let dyn_root_s = config.dyn_root.to_string_lossy().into_owned();

    // 0 = no limit: use large values so VZ clamps to host capacity.
    let memory_mb = if config.memory_mb == 0 {
        u64::MAX / (1024 * 1024)
    } else {
        config.memory_mb
    };
    let cpu_count = if config.cpu_count == 0 {
        usize::MAX
    } else {
        config.cpu_count as usize
    };

    let plan9 = config.mounts.clone();
    let network = config.network;

    // Cmdline picks netstack mode for AllowAll, no kernel NIC otherwise.
    let cmdline = match network {
        NetworkPolicy::AllowAll => format!(
            "console=hvc0 earlyprintk=hvc0 \
             tokimo.session=1 tokimo.init_port=2222 tokimo.guest_listens=1 \
             tokimo.net=netstack tokimo.netstack_port={} \
             net.ifnames=0 biosdevname=0 \
             PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
             HOME=/root TERM=xterm-256color LANG=C.UTF-8",
            NETSTACK_VSOCK_PORT
        ),
        NetworkPolicy::Blocked => "console=hvc0 earlyprintk=hvc0 \
             tokimo.session=1 tokimo.init_port=2222 tokimo.guest_listens=1 \
             tokimo.net=blocked \
             net.ifnames=0 biosdevname=0 \
             PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
             HOME=/root TERM=xterm-256color LANG=C.UTF-8"
            .to_string(),
    };

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .map_err(|e| Error::other(format!("tokio runtime: {e}")))?,
    );

    let rt_for_block = runtime.clone();
    let (vm, vsock_fd, netstack_listener) = rt_for_block.block_on(async move {
        // ---- Boot loader -----------------------------------------------
        let mut boot_loader = LinuxBootLoader::new(&kernel_s)
            .map_err(|e| Error::other(format!("LinuxBootLoader: {e}")))?;
        boot_loader.set_initial_ramdisk(&initrd_s).set_command_line(&cmdline);

        // ---- VM config -------------------------------------------------
        let mut vm_cfg = VirtualMachineConfiguration::new()
            .map_err(|e| Error::other(format!("VirtualMachineConfiguration: {e}")))?;
        let platform =
            GenericPlatform::new().map_err(|e| Error::other(format!("GenericPlatform: {e}")))?;
        vm_cfg
            .set_cpu_count(cpu_count)
            .set_memory_size(memory_mb * 1024 * 1024)
            .set_platform(platform)
            .set_boot_loader(boot_loader)
            .add_entropy_device(
                EntropyDeviceConfiguration::new()
                    .map_err(|e| Error::other(format!("EntropyDevice: {e}")))?,
            )
            .add_socket_device(
                SocketDeviceConfiguration::new()
                    .map_err(|e| Error::other(format!("SocketDevice: {e}")))?,
            );

        let serial = SerialPortConfiguration::virtio_console()
            .map_err(|e| Error::other(format!("SerialPort: {e}")))?;
        let serial_read_fd = serial.read_fd();
        vm_cfg.add_serial_port(serial);

        // No kernel NIC: networking goes through the userspace netstack via
        // vsock + tk0 TUN inside the guest. NetworkPolicy::Blocked uses the
        // same code path with cmdline `tokimo.net=blocked` so init.sh skips
        // the netstack setup.

        // Rootfs (tag "work").
        let rootfs_dir = SharedDirectory::new(&rootfs_s, false)
            .map_err(|e| Error::other(format!("rootfs SharedDirectory: {e}")))?;
        let rootfs_share = SingleDirectoryShare::new(rootfs_dir)
            .map_err(|e| Error::other(format!("rootfs SingleDirectoryShare: {e}")))?;
        let mut rootfs_fs = VirtioFileSystemDeviceConfiguration::new(ROOTFS_TAG)
            .map_err(|e| Error::other(format!("rootfs VirtioFs: {e}")))?;
        rootfs_fs.set_share(rootfs_share);
        vm_cfg.add_directory_share(rootfs_fs);

        // Boot-time Plan9 shares — one virtiofs device per share.
        for share in &plan9 {
            let host_path = share.host_path.to_string_lossy().into_owned();
            let dir = SharedDirectory::new(&host_path, share.read_only)
                .map_err(|e| Error::other(format!("share {} SharedDirectory: {e}", share.name)))?;
            let single = SingleDirectoryShare::new(dir).map_err(|e| {
                Error::other(format!("share {} SingleDirectoryShare: {e}", share.name))
            })?;
            let mut fs = VirtioFileSystemDeviceConfiguration::new(&share.name)
                .map_err(|e| Error::other(format!("share {} VirtioFs: {e}", share.name)))?;
            fs.set_share(single);
            vm_cfg.add_directory_share(fs);
        }

        // Dynamic-share pool (always present, even with no shares yet).
        let dyn_dir = SharedDirectory::new(&dyn_root_s, false)
            .map_err(|e| Error::other(format!("dyn-root SharedDirectory: {e}")))?;
        let dyn_share = SingleDirectoryShare::new(dyn_dir)
            .map_err(|e| Error::other(format!("dyn-root SingleDirectoryShare: {e}")))?;
        let mut dyn_fs = VirtioFileSystemDeviceConfiguration::new(DYN_SHARE_TAG)
            .map_err(|e| Error::other(format!("dyn-root VirtioFs: {e}")))?;
        dyn_fs.set_share(dyn_share);
        vm_cfg.add_directory_share(dyn_fs);

        vm_cfg
            .validate()
            .map_err(|e| Error::other(format!("VM config validation: {e}")))?;

        let vm = vm_cfg
            .build()
            .map_err(|e| Error::other(format!("VM build: {e}")))?;

        tracing::info!(
            kernel = %kernel_s,
            initrd = %initrd_s,
            rootfs = %rootfs_s,
            "starting macOS VZ VM"
        );
        vm.start()
            .await
            .map_err(|e| Error::other(format!("VM start: {e}")))?;

        if vm.state() != VirtualMachineState::Running {
            return Err(Error::other(format!("VM not running: {:?}", vm.state())));
        }

        let socket_devs = vm.socket_devices();
        let socket_dev = socket_devs
            .first()
            .ok_or_else(|| Error::other("no virtio-socket device on running VM"))?;

        // Set up the netstack listener BEFORE the init handshake so that
        // tokimo-tun-pump (started early in init.sh) can connect on its
        // first try. NetworkPolicy::Blocked skips this entirely.
        let netstack_listener = match network {
            NetworkPolicy::AllowAll => Some(
                socket_dev
                    .listen(NETSTACK_VSOCK_PORT)
                    .map_err(|e| Error::other(format!("netstack listen: {e}")))?,
            ),
            NetworkPolicy::Blocked => None,
        };

        let connect_timeout = Duration::from_secs(30);
        let deadline = Instant::now() + connect_timeout;
        let mut conn = None;
        let mut console_log = String::new();
        while Instant::now() < deadline {
            match socket_dev.connect(INIT_VSOCK_PORT).await {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(_) => {
                    if let Some(fd) = serial_read_fd {
                        drain_serial_into(fd, &mut console_log);
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }

        let conn = conn.ok_or_else(|| {
            Error::other(format!(
                "VSOCK connect to guest port {INIT_VSOCK_PORT} timed out after {connect_timeout:?}\nKernel console:\n{console_log}"
            ))
        })?;

        let vsock_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(conn.into_raw_fd()) };
        Ok::<_, Error>((vm, vsock_fd, netstack_listener))
    })?;

    Ok(BootedVm {
        vm,
        vsock: vsock_fd,
        netstack_listener,
        runtime,
    })
}

fn drain_serial_into(fd: std::os::fd::RawFd, out: &mut String) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            out.push_str(&String::from_utf8_lossy(&buf[..n as usize]));
        }
    }
}
