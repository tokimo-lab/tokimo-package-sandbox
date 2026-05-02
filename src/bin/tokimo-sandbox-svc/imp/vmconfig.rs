//! HCS schema 2.x JSON config builder.
//!
//! Layout:
//! * Boot disk: SCSI controller 0 attachment 0 = `rootfs.vhdx` (ext4)
//! * Workspace: zero or more Plan9-over-vsock shares (one per
//!   `Plan9Share` in `ConfigureParams`)
//! * Control: AF_HYPERV/HvSocket, per-session vsock port allocated by
//!   [`alloc_session_init_port`]
//! * Console: COM2 named pipe (kernel kmsg dump)
//!
//! The kernel cmdline tells initramfs-tools to mount `/dev/sda` as the
//! ext4 rootfs. The custom `/sbin/init` shim (built into rootfs.vhdx)
//! takes over PID 1 after switch_root, learns about every share via the
//! `MountManifest` control op, and serves shell sessions over the init
//! channel.

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
/// The kernel cmdline carries only `tokimo.init_port=`; the V2 init
/// learns about every share through a `MountManifest` op on the init
/// vsock channel after `Hello` and before any shells are spawned.
///
/// When `netstack_port` is `Some(port)` a SECOND HvSocket service GUID is
/// registered for the userspace network stack control plane. The guest's
/// `tokimo-tun-pump` connects to it from inside the VM and pumps Ethernet
/// frames over hvsock; the host runs `imp::netstack` to terminate them.
///
/// When `netstack_port` is `None`, no NIC and no netstack channel are
/// exposed (NetworkPolicy::Blocked).
#[allow(clippy::too_many_arguments)]
pub fn build_session_v2_ex(
    vm_id: &str,
    kernel: &Path,
    initrd: &Path,
    rootfs_vhdx: &Path,
    shares: &[V2Share<'_>],
    memory_mb: u64,
    cpu_count: usize,
    init_port: u32,
    netstack_port: Option<u32>,
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
    if let Some(p) = netstack_port {
        let net_entry = serde_json::json!({
            "BindSecurityDescriptor":    "D:(A;;GA;;;WD)",
            "ConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
            "AllowWildcardBinds": true
        });
        svc_table.insert(hvsock_service_id(p), net_entry);
    }
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

    // No NetworkAdapter is added: NetworkPolicy::AllowAll routes through
    // the userspace netstack on `netstack_port` instead of HCN NAT. See
    // `imp::netstack` and the cowork networking RE doc for the rationale.
    let _ = netstack_port;

    let kernel_cmdline = match netstack_port {
        Some(p) => format!(
            "console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw \
             tokimo.session=1 tokimo.init_port={init_port} \
             tokimo.net=netstack tokimo.netstack_port={p}"
        ),
        None => format!(
            "console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw \
             tokimo.session=1 tokimo.init_port={init_port}"
        ),
    };

    // 0 = no limit: omit the field so HCS applies no constraint.
    let mut topology = serde_json::Map::new();
    if memory_mb > 0 {
        topology.insert("Memory".into(), serde_json::json!({ "SizeInMB": memory_mb }));
    }
    if cpu_count > 0 {
        topology.insert("Processor".into(), serde_json::json!({ "Count": cpu_count }));
    }

    let vm = serde_json::json!({
        "ComputeTopology": topology,
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

/// Build a ModifySettingRequest JSON for adding/removing a single
/// Plan9 share at runtime via `HcsModifyComputeSystem`.
///
/// Schema 2.x format:
/// `{"ResourceUri":"VirtualMachine/Devices/Plan9/Shares",
///   "Settings":{"Name":..,"AccessName":..,"Path":..,"Port":..},
///   "RequestType":"Add"|"Remove"}`
///
/// As with [`build_session_v2`], no `ReadOnly` field is emitted —
/// HCS Plan9 rejects it; read-only is enforced guest-side via the
/// 9p mount flags carried over the AddMount op.
pub fn plan9_modify_request(name: &str, host_path: &Path, port: u32, request_type: &str) -> String {
    let settings = serde_json::json!({
        "Name": name,
        "AccessName": name,
        "Path": strip_extended_prefix(host_path),
        "Port": port,
    });
    serde_json::json!({
        "ResourcePath": "VirtualMachine/Devices/Plan9/Shares",
        "Settings": settings,
        "RequestType": request_type,
    })
    .to_string()
}

/// Allocate a Plan9 share port for a runtime-added share. Currently a
/// thin alias of [`alloc_share_port`] so the boot-time and runtime
/// allocators stay in lock-step.
pub fn alloc_plan9_port() -> u32 {
    alloc_share_port()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_paths() -> (PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from(r"C:\k"),
            PathBuf::from(r"C:\i"),
            PathBuf::from(r"C:\persist.vhdx"),
        )
    }

    #[test]
    fn v2_multi_share_schema_and_cmdline() {
        let (k, i, rootfs) = dummy_paths();
        let work = PathBuf::from(r"C:\work");
        let ro = PathBuf::from(r"C:\readonly");
        let shares = [
            V2Share {
                host_path: &work,
                name: "s0",
                port: alloc_share_port(),
                read_only: false,
            },
            V2Share {
                host_path: &ro,
                name: "s1",
                port: alloc_share_port(),
                read_only: true,
            },
        ];
        let s = build_session_v2_ex("id", &k, &i, &rootfs, &shares, 1024, 2, 0x4000_0001, None);
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
        let port = arr[1]["Port"].as_u64().unwrap();
        assert!(
            (50100..58292).contains(&(port as u32)),
            "share port {port} out of HCS-Plan9 range"
        );

        // HvSocket service table registers ONLY the init port.
        let table = v["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
            .as_object()
            .unwrap();
        assert!(table.contains_key(&hvsock_service_id(0x4000_0001)));
        let sp0 = arr[0]["Port"].as_u64().unwrap() as u32;
        let sp1 = arr[1]["Port"].as_u64().unwrap() as u32;
        assert!(!table.contains_key(&hvsock_service_id(sp0)));
        assert!(!table.contains_key(&hvsock_service_id(sp1)));

        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("tokimo.init_port=1073741825"));
        assert!(cmdline.contains("root=/dev/sda"));
        assert!(cmdline.contains("rootfstype=ext4"));
        assert!(cmdline.contains("console=ttyS1"));
        // The legacy single-share work_port must not leak into v2 cmdline.
        assert!(
            !cmdline.contains("tokimo.work_port="),
            "v2 cmdline must not carry tokimo.work_port=, got: {cmdline}"
        );
    }

    #[test]
    fn v2_zero_shares_and_topology() {
        let (k, i, rootfs) = dummy_paths();
        let s = build_session_v2_ex("vm-foo", &k, &i, &rootfs, &[], 4096, 8, 0x4000_00AB, None);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        assert_eq!(v["VirtualMachine"]["ComputeTopology"]["Memory"]["SizeInMB"], 4096);
        assert_eq!(v["VirtualMachine"]["ComputeTopology"]["Processor"]["Count"], 8);

        let arr = v["VirtualMachine"]["Devices"]["Plan9"]["Shares"].as_array().unwrap();
        assert!(arr.is_empty(), "no shares means empty array");

        // COM2 named pipe carries the vm_id.
        let pipe = v["VirtualMachine"]["Devices"]["ComPorts"]["1"]["NamedPipe"]
            .as_str()
            .unwrap();
        assert!(pipe.contains("vm-foo"));

        // No NetworkAdapter ever (userspace netstack handles egress).
        assert!(
            v["VirtualMachine"]["Devices"].get("NetworkAdapters").is_none()
                && v["VirtualMachine"]["Devices"].get("NetworkAdapter").is_none(),
            "no NIC expected — netstack uses hvsock"
        );
    }

    #[test]
    fn v2_with_netstack_port() {
        let (k, i, rootfs) = dummy_paths();
        let port: u32 = 0x4000_00CD;
        let s = build_session_v2_ex("id", &k, &i, &rootfs, &[], 1024, 2, 0x4000_0002, Some(port));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        // Cmdline must select netstack mode and carry the port.
        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("tokimo.net=netstack"));
        assert!(cmdline.contains(&format!("tokimo.netstack_port={port}")));

        // The HvSocket service table must include the netstack service id.
        let table = v["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
            .as_object()
            .unwrap();
        assert!(table.contains_key(&hvsock_service_id(port)));
    }

    #[test]
    fn hvsock_service_id_format() {
        assert_eq!(hvsock_service_id(0x4000_0001), "40000001-FACB-11E6-BD58-64006A7986D3");
        assert_eq!(hvsock_service_id(50002), "0000C352-FACB-11E6-BD58-64006A7986D3");
    }

    #[test]
    fn alloc_session_init_port_is_in_high_range_and_unique() {
        let a = alloc_session_init_port();
        let b = alloc_session_init_port();
        assert_ne!(a, b);
        for p in [a, b] {
            assert_eq!(p & 0xFF00_0000, 0x4000_0000, "port {p:#x} out of range");
        }
    }

    #[test]
    fn share_port_allocator_distinct_from_init() {
        let i1 = alloc_session_init_port();
        let s1 = alloc_share_port();
        let s2 = alloc_share_port();
        assert_ne!(i1, s1);
        assert_ne!(s1, s2);
        assert_eq!(i1 & 0xFF00_0000, 0x4000_0000);
        assert!((50100..58292).contains(&s1));
        assert!((50100..58292).contains(&s2));
    }
}
