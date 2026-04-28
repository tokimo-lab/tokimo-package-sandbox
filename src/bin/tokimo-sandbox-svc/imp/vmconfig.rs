//! HCS schema 2.x JSON config builder.
//!
//! Two boot modes:
//!   * VHDX: rootfs.vhdx attached as SCSI disk 0:0; workspace shared via
//!     Plan9 (tag `work`); kernel cmdline contains `tokimo.boot=vhdx`.
//!   * Plan9 root (legacy): workspace IS the rootfs; mounted via Plan9
//!     (tag `rootshare`); kernel cmdline does not set `tokimo.boot`.
//!
//! No NetworkAdapter is added — network policy is enforced by simply not
//! attaching a NIC. AllowAll-with-NAT support is tracked separately and
//! requires HCN endpoint plumbing.

#![cfg(target_os = "windows")]

use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub fn build(
    _vm_id: &str,
    kernel: &Path,
    initrd: &Path,
    rootfs_vhdx: Option<&Path>,
    workspace: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> String {
    let kernel_s = kernel.to_string_lossy();
    let initrd_s = initrd.to_string_lossy();
    let workspace_s = workspace.to_string_lossy();

    let mut devices = serde_json::Map::new();

    // Plan9 share for workspace.
    devices.insert(
        "Plan9".into(),
        serde_json::json!({
            "Shares": [
                {
                    "Name": if rootfs_vhdx.is_some() { "work" } else { "rootshare" },
                    "Path": workspace_s,
                    "Port": 564,
                    "Flags": 0
                }
            ]
        }),
    );

    // SCSI disk attachment for the VHDX.
    if let Some(vhdx) = rootfs_vhdx {
        devices.insert(
            "Scsi".into(),
            serde_json::json!({
                "primary": {
                    "Attachments": {
                        "0": {
                            "Type": "VirtualDisk",
                            "Path": vhdx.to_string_lossy()
                        }
                    }
                }
            }),
        );
    }

    // Build kernel command line.
    let boot_arg = if rootfs_vhdx.is_some() { " tokimo.boot=vhdx" } else { "" };
    let kernel_args = format!("console=ttyS0 quiet loglevel=3{boot_arg} run={cmd_b64}");

    serde_json::json!({
        "SchemaVersion": { "Major": 2, "Minor": 0 },
        "Owner": "tokimo-sandbox-svc",
        "VirtualMachine": {
            "ComputeTopology": {
                "Memory": { "Backing": "Virtual", "SizeInMB": memory_mb },
                "Processor": { "Count": cpu_count, "Maximum": cpu_count, "Weight": 100 }
            },
            "Chipset": {
                "LinuxKernel": {
                    "KernelPath": kernel_s,
                    "InitrdPath": initrd_s,
                    "Arguments": kernel_args
                }
            },
            "Devices": devices,
            "StopOnGuestCrash": true
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn legacy_plan9_root_has_no_scsi() {
        let s = build(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            None,
            &PathBuf::from(r"C:\w"),
            "Y21k",
            512,
            2,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["VirtualMachine"]["Devices"]["Scsi"].is_null());
        assert!(v["VirtualMachine"]["Devices"]["Plan9"]["Shares"][0]["Name"]
            .as_str()
            .unwrap()
            .eq("rootshare"));
        assert!(!v["VirtualMachine"]["Chipset"]["LinuxKernel"]["Arguments"]
            .as_str()
            .unwrap()
            .contains("tokimo.boot"));
    }

    #[test]
    fn vhdx_mode_has_scsi_and_boot_flag() {
        let s = build(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            Some(&PathBuf::from(r"C:\rootfs.vhdx")),
            &PathBuf::from(r"C:\w"),
            "Y21k",
            512,
            2,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["VirtualMachine"]["Devices"]["Scsi"]["primary"]["Attachments"]["0"]["Type"]
            .as_str()
            .unwrap()
            .eq("VirtualDisk"));
        assert_eq!(
            v["VirtualMachine"]["Devices"]["Plan9"]["Shares"][0]["Name"]
                .as_str()
                .unwrap(),
            "work"
        );
        assert!(v["VirtualMachine"]["Chipset"]["LinuxKernel"]["Arguments"]
            .as_str()
            .unwrap()
            .contains("tokimo.boot=vhdx"));
    }
}
