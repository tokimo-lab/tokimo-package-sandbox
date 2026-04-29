//! HCS schema 2.x JSON config builder.
//!
//! Cowork-style layout:
//!   * Boot disk: SCSI controller 0 attachment 0 = `rootfs.vhdx` (ext4)
//!   * Workspace: Plan9-over-vsock single share `work` on `PORT_WORK`
//!   * Control:   AF_HYPERV/HvSocket on `PORT_INIT_CONTROL` (session mode)
//!   * Console:   COM2 named pipe (kernel kmsg dump)
//!
//! The kernel cmdline tells initramfs-tools to mount `/dev/sda` as the
//! ext4 rootfs. The custom `/sbin/init` shim (built into rootfs.vhdx)
//! takes over PID 1 after switch_root, mounts the workspace via
//! `vsock9p`, and exec's the Rust agent.

#![cfg(target_os = "windows")]

use std::path::Path;

fn strip_extended_prefix(p: &Path) -> String {
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        s.into_owned()
    }
}

/// vsock port for the workspace Plan9 share.
pub const PORT_WORK: u32 = 50002;
/// AF_VSOCK port the init binary listens on for the host↔guest control
/// protocol in session mode (default; per-session overrides may be used).
/// Maps to HvSocket service GUID `0000C353-FACB-11E6-BD58-64006A7986D3`.
pub const PORT_INIT_CONTROL: u32 = 50003;

/// Allocate a unique vsock port per session so concurrent VMs get distinct
/// HvSocket service GUIDs (Hyper-V requires `(VmId, ServiceId)` to be
/// unique for a host-side WILDCARD listener; binding a specific child's
/// VmId from the parent partition fails with WSAEACCES).
pub fn alloc_session_init_port() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    // Use a large, unallocated u32 range. Wraps every ~16M sessions which
    // is fine for any realistic process lifetime.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // 0x40000000 .. 0x40FFFFFF — avoids well-known low-port range and
    // keeps the encoded service GUID prefix recognizable in logs.
    0x4000_0000 | (n & 0x00FF_FFFF)
}

/// Build the HvSocket service GUID for a given vsock port.
/// Hyper-V's mapping: GUID = `XXXXXXXX-FACB-11E6-BD58-64006A7986D3`,
/// where `XXXXXXXX` is the vsock port in big-endian hex.
pub fn hvsock_service_id(port: u32) -> String {
    format!("{:08X}-FACB-11E6-BD58-64006A7986D3", port)
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    vm_id: &str,
    kernel: &Path,
    initrd: &Path,
    rootfs_vhdx: &Path,
    workspace: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> String {
    build_ex(
        vm_id,
        kernel,
        initrd,
        rootfs_vhdx,
        workspace,
        cmd_b64,
        memory_mb,
        cpu_count,
        false,
        None,
        PORT_INIT_CONTROL,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_ex(
    vm_id: &str,
    kernel: &Path,
    initrd: &Path,
    rootfs_vhdx: &Path,
    workspace: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
    session: bool,
    runtime_id: Option<&str>,
    init_port: u32,
) -> String {
    let kernel_s = strip_extended_prefix(kernel);
    let initrd_s = strip_extended_prefix(initrd);
    let rootfs_s = strip_extended_prefix(rootfs_vhdx);
    let workspace_s = strip_extended_prefix(workspace);

    // SCSI controller 0, attachment 0: the rootfs VHDX. The guest's
    // initramfs-tools sees this as /dev/sda.
    let scsi = serde_json::json!({
        "0": {
            "Attachments": {
                "0": {
                    "Type": "VirtualDisk",
                    "Path": rootfs_s,
                    "ReadOnly": false
                }
            }
        }
    });

    // Single Plan9-over-vsock share for the user workspace. The guest
    // mounts it at /mnt/work via vsock9p (using `trans=fd`).
    let plan9 = serde_json::json!({
        "Shares": [
            {
                "Name": "work",
                "AccessName": "work",
                "Path": workspace_s,
                "Port": PORT_WORK
            }
        ]
    });

    let mut devices = serde_json::Map::new();
    devices.insert("Scsi".into(), scsi);
    devices.insert("Plan9".into(), plan9);

    // HvSocket device — required for AF_HYPERV host↔guest control plane.
    // Cowork strings reveal both DefaultBind and DefaultConnect SDDLs, but
    // the most permissive form `D:(A;;GA;;;WD)` (no protected flag) matches
    // exactly what cowork-svc embeds. Wide-open ACL — guest is implicitly
    // trusted because we own the VM.
    // Per-service config: explicitly register PORT_INIT_CONTROL with
    // AllowWildcardBinds=true so the host listener bound on
    // HV_GUID_WILDCARD VmId is reachable from this VM. Cowork uses the
    // same pattern (strings show ServiceTable + AllowWildcardBinds).
    let init_svc_guid = hvsock_service_id(init_port);
    devices.insert(
        "HvSocket".into(),
        serde_json::json!({
            "HvSocketConfig": {
                "DefaultBindSecurityDescriptor":    "D:(A;;GA;;;WD)",
                "DefaultConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
                "ServiceTable": {
                    init_svc_guid: {
                        "BindSecurityDescriptor":    "D:(A;;GA;;;WD)",
                        "ConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
                        "AllowWildcardBinds": true
                    }
                }
            }
        }),
    );

    // COM port wiring depends on session vs. one-shot mode.
    if session {
        // Session mode: COM1 is unused (init talks via AF_HYPERV vsock).
        // COM2 is the kernel console + diagnostic dump.
        devices.insert(
            "ComPorts".into(),
            serde_json::json!({
                "1": { "NamedPipe": format!(r"\\.\pipe\tokimo-vm-com2-{}", vm_id) }
            }),
        );
    } else {
        devices.insert(
            "ComPorts".into(),
            serde_json::json!({
                "0": { "NamedPipe": format!(r"\\.\pipe\tokimo-vm-com1-{}", vm_id) }
            }),
        );
    }

    let kernel_cmdline = if session {
        // ttyS1 = COM2 for kernel logs. tokimo.* parsed by /sbin/init shim.
        format!(
            "console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw \
             tokimo.session=1 tokimo.work_port={PORT_WORK} \
             tokimo.init_port={init_port}"
        )
    } else {
        format!(
            "console=ttyS0 loglevel=7 root=/dev/sda rootfstype=ext4 rw \
             tokimo.work_port={PORT_WORK} run={cmd_b64}"
        )
    };

    let vm = serde_json::json!({
        "ComputeTopology": {
            "Memory": { "SizeInMB": memory_mb },
            "Processor": { "Count": cpu_count }
        },
        "Chipset": {
            "LinuxKernelDirect": {
                "KernelFilePath": kernel_s,
                "InitRdPath": initrd_s,
                "KernelCmdLine": kernel_cmdline
            }
        },
        "Devices": devices
    });

    let top = serde_json::json!({
        "SchemaVersion": { "Major": 2, "Minor": 5 },
        "Owner": "tokimo-sandbox-svc",
        "VirtualMachine": vm
    });
    let _ = runtime_id; // HCS auto-assigns; we query it back via get_runtime_id.
    top.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn schema_has_scsi_vhdx_and_plan9_workspace() {
        let s = build(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            &PathBuf::from(r"C:\rootfs.vhdx"),
            &PathBuf::from(r"C:\work"),
            "Y21k",
            512,
            2,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let scsi = &v["VirtualMachine"]["Devices"]["Scsi"]["0"]["Attachments"]["0"];
        assert_eq!(scsi["Type"], "VirtualDisk");
        assert_eq!(scsi["Path"], r"C:\rootfs.vhdx");
        let shares = v["VirtualMachine"]["Devices"]["Plan9"]["Shares"]
            .as_array()
            .expect("shares");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0]["Name"], "work");
        assert_eq!(shares[0]["Port"], PORT_WORK);
    }

    #[test]
    fn cmdline_carries_root_and_ports() {
        let s = build(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            &PathBuf::from(r"C:\rootfs.vhdx"),
            &PathBuf::from(r"C:\work"),
            "Y21k",
            512,
            2,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("root=/dev/sda"));
        assert!(cmdline.contains("rootfstype=ext4"));
        assert!(cmdline.contains("tokimo.work_port=50002"));
        assert!(cmdline.contains("run=Y21k"));
    }

    #[test]
    fn session_cmdline_has_init_port() {
        let s = build_ex(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            &PathBuf::from(r"C:\rootfs.vhdx"),
            &PathBuf::from(r"C:\work"),
            "",
            512,
            2,
            true,
            None,
            PORT_INIT_CONTROL,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("tokimo.session=1"));
        assert!(cmdline.contains("tokimo.init_port=50003"));
        assert!(cmdline.contains("console=ttyS1"));
    }
}
