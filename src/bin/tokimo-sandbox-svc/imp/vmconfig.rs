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

/// Allocate a unique vsock port for a per-session Plan9 share. We stay
/// in the same low decimal range as `PORT_WORK` (50002) because HCS's
/// internal Plan9 implementation rejects very high port values during
/// `HcsCreateComputeSystem` (`0x8037010D` "Construct" failure).
pub fn alloc_share_port() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // 50100..=58291 — well clear of PORT_WORK (50002) and PORT_INIT_CONTROL,
    // small enough for HCS Plan9 to accept.
    50100 + (n % 8192)
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

/// One share for a V2 multi-share session config.
pub struct V2Share<'a> {
    pub host_path: &'a Path,
    pub name: &'a str,
    pub port: u32,
    pub read_only: bool,
}

/// Build an HCS Schema 2.x JSON config for **session mode V2** with an
/// arbitrary list of Plan9-over-vsock shares and an explicit rootfs
/// VHDX. The rootfs is mounted on SCSI controller 0 attachment 0
/// (`/dev/sda`) read-write — persistent vs ephemeral lifecycle is
/// managed at a higher layer (`vhdx_pool`).
///
/// The kernel cmdline carries only `tokimo.init_port=`; the legacy
/// `tokimo.work_port=` is intentionally absent because the V2 init
/// learns about every share through a `MountManifest` op on the init
/// vsock channel after `Hello` and before any shells are spawned.
#[allow(clippy::too_many_arguments)]
pub fn build_session_v2(
    vm_id: &str,
    kernel: &Path,
    initrd: &Path,
    rootfs_vhdx: &Path,
    shares: &[V2Share<'_>],
    memory_mb: u64,
    cpu_count: usize,
    init_port: u32,
) -> String {
    let kernel_s = strip_extended_prefix(kernel);
    let initrd_s = strip_extended_prefix(initrd);
    let rootfs_s = strip_extended_prefix(rootfs_vhdx);

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

    let plan9_shares: Vec<serde_json::Value> = shares
        .iter()
        .map(|s| {
            // NOTE: do NOT add a `ReadOnly` field here — HCS schema 2.5
            // rejects Plan9.Shares entries containing it with `0x8037010D`
            // ("Construct" failure). RO is enforced guest-side via the
            // mount manifest's `MS_RDONLY` flag.
            let _ = s.read_only;
            serde_json::json!({
                "Name": s.name,
                "AccessName": s.name,
                "Path": strip_extended_prefix(s.host_path),
                "Port": s.port
            })
        })
        .collect();
    let plan9 = serde_json::json!({ "Shares": plan9_shares });

    let mut devices = serde_json::Map::new();
    devices.insert("Scsi".into(), scsi);
    devices.insert("Plan9".into(), plan9);

    // Register the per-session init-control HvSocket service GUID so the
    // WILDCARD-bound listener on the host is reachable from this VM.
    //
    // Plan9 share ports are NOT added to this table — HCS provides the
    // 9p server internally for each `Plan9.Shares[i]` entry and owns the
    // host-side endpoint on `Port`. Adding them here (or binding our own
    // listener) would race HCS's listener for the same vsock service GUID.
    let mut svc_table = serde_json::Map::new();
    let entry = serde_json::json!({
        "BindSecurityDescriptor":    "D:(A;;GA;;;WD)",
        "ConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
        "AllowWildcardBinds": true
    });
    svc_table.insert(hvsock_service_id(init_port), entry);
    let _ = shares; // ports referenced via Plan9.Shares above
    devices.insert(
        "HvSocket".into(),
        serde_json::json!({
            "HvSocketConfig": {
                "DefaultBindSecurityDescriptor":    "D:(A;;GA;;;WD)",
                "DefaultConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
                "ServiceTable": svc_table
            }
        }),
    );

    devices.insert(
        "ComPorts".into(),
        serde_json::json!({
            "1": { "NamedPipe": format!(r"\\.\pipe\tokimo-vm-com2-{}", vm_id) }
        }),
    );

    let kernel_cmdline = format!(
        "console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw \
         tokimo.session=1 tokimo.init_port={init_port}"
    );

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

    #[test]
    fn v2_multi_share_schema_and_cmdline() {
        let work = PathBuf::from(r"C:\work");
        let ro = PathBuf::from(r"C:\readonly");
        let rootfs = PathBuf::from(r"C:\persist.vhdx");
        let shares = [
            V2Share {
                host_path: &work,
                name: "s0",
                port: 0x4100_0001,
                read_only: false,
            },
            V2Share {
                host_path: &ro,
                name: "s1",
                port: 0x4100_0002,
                read_only: true,
            },
        ];
        let s = build_session_v2(
            "id",
            &PathBuf::from(r"C:\k"),
            &PathBuf::from(r"C:\i"),
            &rootfs,
            &shares,
            1024,
            2,
            0x4000_0001,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        // SCSI carries the persistent rootfs path.
        assert_eq!(
            v["VirtualMachine"]["Devices"]["Scsi"]["0"]["Attachments"]["0"]["Path"],
            r"C:\persist.vhdx"
        );

        // Plan9 has both shares, in order. RO flag is enforced guest-side
        // via the mount manifest — HCS schema 2.5 rejects any `ReadOnly`
        // field on Plan9.Shares with `0x8037010D`.
        let arr = v["VirtualMachine"]["Devices"]["Plan9"]["Shares"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["Name"], "s0");
        assert!(arr[0].get("ReadOnly").is_none(), "Plan9 share must NOT carry ReadOnly");
        assert_eq!(arr[1]["Name"], "s1");
        assert!(arr[1].get("ReadOnly").is_none(), "Plan9 share must NOT carry ReadOnly");
        // Share port is in the low decimal range so HCS Plan9 accepts it.
        let port = arr[1]["Port"].as_u64().unwrap();
        assert!(
            (50100..58292).contains(&(port as u32)),
            "share port {port} out of HCS-Plan9 range"
        );

        // HvSocket service table registers ONLY the init port — share
        // ports are owned by HCS's internal Plan9 server.
        let table = v["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
            .as_object()
            .unwrap();
        assert!(table.contains_key(&hvsock_service_id(0x4000_0001)));
        assert!(!table.contains_key(&hvsock_service_id(0x4100_0001)));
        assert!(!table.contains_key(&hvsock_service_id(0x4100_0002)));

        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("tokimo.init_port=1073741825"));
        // V2 cmdline must NOT carry the legacy single-share work_port.
        assert!(
            !cmdline.contains("tokimo.work_port="),
            "v2 cmdline should not carry tokimo.work_port=, got: {cmdline}"
        );
    }

    #[test]
    fn share_port_allocator_distinct_from_init() {
        let i1 = alloc_session_init_port();
        let s1 = alloc_share_port();
        let s2 = alloc_share_port();
        assert_ne!(i1, s1);
        assert_ne!(s1, s2);
        // Init ports stay in the high 0x4000_0000 range; share ports stay in
        // a low decimal range that HCS Plan9 accepts.
        assert_eq!(i1 & 0xFF00_0000, 0x4000_0000);
        assert!((50100..58292).contains(&s1));
        assert!((50100..58292).contains(&s2));
    }
}
