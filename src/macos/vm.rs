//! VM bootstrap using arcbox-vz.
//!
//! Boots a Linux VM with kernel/initrd/rootfs from `<repo>/vm/`, configures
//! virtio-vsock, and returns a connected socket to the guest's init.

use std::env;
use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader,
    SocketDeviceConfiguration, VirtualMachine, VirtualMachineConfiguration,
};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

use crate::api::Plan9Share;
use crate::error::{Error, Result};

/// Default vsock port for init protocol connection.
pub(crate) const INIT_VSOCK_PORT: u32 = 1234;

/// VM configuration parameters.
#[derive(Debug, Clone)]
pub struct VmConfig {
    pub memory_mb: u64,
    pub cpu_count: u32,
    pub plan9_shares: Vec<Plan9Share>,
    pub user_data_name: String,
}

/// Find VM artifacts (kernel/initrd/rootfs) by walking up from current_exe()
/// and current_dir(), looking for a `vm/` directory containing all three files.
/// Honours `TOKIMO_VM_DIR` env override.
pub fn find_vm_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("TOKIMO_VM_DIR") {
        let p = PathBuf::from(dir);
        if validate_vm_dir(&p) {
            return Ok(p);
        }
        return Err(Error::other(format!(
            "TOKIMO_VM_DIR={} does not contain vmlinuz, initrd.img, rootfs.ext4",
            p.display()
        )));
    }

    // Try current_exe() parent chain.
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.as_path();
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

    // Try current_dir() parent chain.
    if let Ok(cwd) = env::current_dir() {
        let mut cur = cwd.as_path();
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

    Err(Error::other(
        "VM artifacts not found. Set TOKIMO_VM_DIR or ensure <repo>/vm/ exists with vmlinuz, initrd.img, rootfs.ext4.",
    ))
}

fn validate_vm_dir(dir: &Path) -> bool {
    dir.join("vmlinuz").is_file()
        && dir.join("initrd.img").is_file()
        && (dir.join("rootfs.ext4").is_file() || dir.join("rootfs.img").is_file())
}

/// Boot a Linux VM and return (VirtualMachine handle, vsock OwnedFd connected to guest init).
///
/// ## Implementation notes
///
/// This is a structural placeholder using `arcbox-vz` symbols. The actual
/// arcbox-vz API on macOS may differ. Key integration points marked TODO:
///
/// - VirtualMachineConfiguration builder pattern
/// - VsockListener / connect logic (may require `tokio` runtime or blocking)
/// - Rootfs mounting: arcbox-vz may require a disk image; if so, use
///   `VirtioBlockDeviceConfiguration` instead of virtiofs
///
/// If you're filling in real arcbox-vz wiring, consult:
/// - https://docs.rs/arcbox-vz
/// - `src/macos/vz.rs` (existing helper code, if still useful)
pub fn boot_vm(config: &VmConfig) -> Result<(Arc<VirtualMachine>, OwnedFd)> {
    let vm_dir = find_vm_dir()?;
    let kernel_path = vm_dir.join("vmlinuz");
    let initrd_path = vm_dir.join("initrd.img");
    let rootfs_path = if vm_dir.join("rootfs.ext4").exists() {
        vm_dir.join("rootfs.ext4")
    } else {
        vm_dir.join("rootfs.img")
    };

    let kernel_str = kernel_path.to_string_lossy().into_owned();
    let initrd_str = initrd_path.to_string_lossy().into_owned();

    // Build kernel cmdline: console, init, vsock port.
    let cmdline = format!(
        "console=hvc0 quiet loglevel=3 init=/tokimo-sandbox-init tokimo.init_port={}",
        INIT_VSOCK_PORT
    );

    // TODO: adapt to real arcbox-vz API. The following is a structural sketch.
    let mut boot_loader = LinuxBootLoader::new(&kernel_str)
        .map_err(|e| Error::other(format!("LinuxBootLoader::new: {e}")))?;
    boot_loader
        .set_initial_ramdisk(&initrd_str)
        .set_command_line(&cmdline);

    let mut vm_config = VirtualMachineConfiguration::new()
        .map_err(|e| Error::other(format!("VirtualMachineConfiguration::new: {e}")))?;
    vm_config
        .set_cpu_count(config.cpu_count as usize)
        .set_memory_size(config.memory_mb * 1024 * 1024)
        .set_platform(
            GenericPlatform::new()
                .map_err(|e| Error::other(format!("GenericPlatform::new: {e}")))?,
        )
        .set_boot_loader(boot_loader)
        .add_entropy_device(
            EntropyDeviceConfiguration::new()
                .map_err(|e| Error::other(format!("EntropyDeviceConfiguration::new: {e}")))?,
        )
        .add_socket_device(
            SocketDeviceConfiguration::new()
                .map_err(|e| Error::other(format!("SocketDeviceConfiguration::new: {e}")))?,
        );

    // TODO: Mount rootfs. Options:
    // 1. VirtioBlockDeviceConfiguration (disk image)
    // 2. VirtioFileSystemDeviceConfiguration (virtiofs) — if arcbox-vz supports
    //
    // For now, return NotImplemented if rootfs is required.
    // The user will fill in the real mounting code later.
    if !rootfs_path.exists() {
        return Err(Error::not_implemented(
            "rootfs mounting in macOS VM bootstrap",
        ));
    }

    // Validate configuration.
    vm_config
        .validate()
        .map_err(|e| Error::other(format!("VM config validation: {e}")))?;

    // Start the VM.
    let vm = VirtualMachine::new(vm_config, None)
        .map_err(|e| Error::other(format!("VirtualMachine::new: {e}")))?;
    let vm = Arc::new(vm);

    // TODO: arcbox-vz API for starting the VM. May be `vm.start()` or similar.
    // For now, assume `vm` is already running or auto-starts.
    // Real code might need:
    //   vm.start().map_err(...)?;

    // TODO: Connect to guest vsock. This requires a vsock listener or connect
    // call. The exact API depends on arcbox-vz's vsock support. Structural
    // placeholder:
    //
    // Option A: Host-side listener (AF_VSOCK bind to wildcard CID + port 1234)
    // Option B: Host connects to guest CID + port (if arcbox-vz provides guest CID)
    //
    // For now, return NotImplemented.
    let vsock_fd = connect_to_guest_vsock(&vm, INIT_VSOCK_PORT)?;

    Ok((vm, vsock_fd))
}

/// Connect to the guest's vsock port. This is a structural placeholder.
///
/// ## Real implementation notes (TODO by user)
///
/// macOS AF_VSOCK support via Virtualization.framework is exposed through:
/// - `VZVirtioSocketDeviceConfiguration` (already added via `add_socket_device`)
/// - Host-side API to get guest CID and connect
///
/// Typical flow:
/// 1. After `vm.start()`, get guest CID (may be dynamic or fixed to 3)
/// 2. Use nix::sys::socket or libc to create AF_VSOCK socket
/// 3. Connect to (guest_cid, INIT_VSOCK_PORT)
///
/// Alternatively, if arcbox-vz provides a `VsockListener` or similar:
/// 4. Bind to (VMADDR_CID_HOST=2, port=1234) and accept guest connection
///
/// For now, return NotImplemented.
fn connect_to_guest_vsock(vm: &VirtualMachine, port: u32) -> Result<OwnedFd> {
    // Placeholder: create a dummy STREAM socket to satisfy type requirements.
    // Real code replaces this with AF_VSOCK connect.
    let _vm = vm; // suppress unused warning
    let _port = port;

    // Uncomment and adapt once arcbox-vz API is known:
    // let sock = socket(
    //     AddressFamily::Vsock,
    //     SockType::Stream,
    //     SockFlag::SOCK_CLOEXEC,
    //     None,
    // )
    // .map_err(|e| Error::other(format!("socket(AF_VSOCK): {e}")))?;
    //
    // let guest_cid = 3; // or vm.guest_cid()
    // let addr = VsockAddr::new(guest_cid, port);
    // connect(sock.as_raw_fd(), &addr)
    //     .map_err(|e| Error::other(format!("connect vsock: {e}")))?;
    // Ok(sock)

    Err(Error::not_implemented(
        "vsock connection to guest (arcbox-vz API TBD)",
    ))
}
