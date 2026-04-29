//! HCS schema 2.x JSON config builder.

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

/// vsock ports for the two Plan9 shares. Hyper-V's HCS Plan9 device always
/// exposes 9p over AF_VSOCK on the host CID; the guest's `vsock9p` helper
/// connects to these ports.
pub const PORT_ROOTSHARE: u32 = 50001;
pub const PORT_WORK: u32 = 50002;

#[allow(clippy::too_many_arguments)]
pub fn build(
    _vm_id: &str,
    kernel: &Path,
    initrd: &Path,
    rootfs_dir: &Path,
    workspace: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> String {
    let kernel_s = strip_extended_prefix(kernel);
    let initrd_s = strip_extended_prefix(initrd);
    let rootfs_s = strip_extended_prefix(rootfs_dir);
    let workspace_s = strip_extended_prefix(workspace);

    // Two Plan9 shares: rootshare (the Debian rootfs) and work (the user
    // workspace). Each gets its own vsock port — the guest mounts both via
    // `vsock9p` from inside the initrd and switch_root's into rootshare.
    //
    // NOTE: Without `Port`, HCS Plan9 does NOT default to virtio-fs (HCS
    // has no virtio-fs backend on Hyper-V). Plan9-over-vsock is the only
    // shared-folder transport.
    let plan9 = serde_json::json!({
        "Shares": [
            {
                "Name": "rootshare",
                "AccessName": "rootshare",
                "Path": rootfs_s,
                "Port": PORT_ROOTSHARE
            },
            {
                "Name": "work",
                "AccessName": "work",
                "Path": workspace_s,
                "Port": PORT_WORK
            }
        ]
    });

    let mut devices = serde_json::Map::new();
    devices.insert("Plan9".into(), plan9);

    // Redirect COM1 to a named pipe per VM so callers (or a tail loop in the
    // service) can capture serial output for diagnostics.
    devices.insert(
        "ComPorts".into(),
        serde_json::json!({
            "0": {
                "NamedPipe": format!(r"\\.\pipe\tokimo-vm-com1-{}", _vm_id)
            }
        }),
    );

    let kernel_cmdline = format!(
        "console=ttyS0 loglevel=7 tokimo.rootshare_port={PORT_ROOTSHARE} \
         tokimo.work_port={PORT_WORK} run={cmd_b64}"
    );

    serde_json::json!({
        "SchemaVersion": { "Major": 2, "Minor": 5 },
        "Owner": "tokimo-sandbox-svc",
        "VirtualMachine": {
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
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn schema_has_two_plan9_shares_with_ports() {
        let s = build(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            &PathBuf::from(r"C:\rootfs"),
            &PathBuf::from(r"C:\work"),
            "Y21k",
            512,
            2,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let shares = v["VirtualMachine"]["Devices"]["Plan9"]["Shares"]
            .as_array()
            .expect("shares array");
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0]["Name"], "rootshare");
        assert_eq!(shares[0]["Port"], PORT_ROOTSHARE);
        assert_eq!(shares[1]["Name"], "work");
        assert_eq!(shares[1]["Port"], PORT_WORK);
    }

    #[test]
    fn cmdline_carries_ports_and_run() {
        let s = build(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            &PathBuf::from(r"C:\rootfs"),
            &PathBuf::from(r"C:\work"),
            "Y21k",
            512,
            2,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("tokimo.rootshare_port=50001"));
        assert!(cmdline.contains("tokimo.work_port=50002"));
        assert!(cmdline.contains("run=Y21k"));
    }
}
