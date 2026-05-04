//! HCS schema 2.x JSON config builder.
//!
//! Layout:
//! * Boot disk: SCSI controller 0 attachment 0 = `rootfs.vhdx` (ext4)
//! * User mounts: FUSE-over-vsock (host FuseHost ↔ guest
//!   `tokimo-sandbox-fuse`), port allocated by [`alloc_fuse_port`]
//! * Control: AF_HYPERV/HvSocket, per-session vsock port allocated by
//!   [`alloc_session_init_port`]
//! * Console: COM2 named pipe (kernel kmsg dump)
//!
//! The kernel cmdline tells initramfs-tools to mount `/dev/sda` as the
//! ext4 rootfs. The custom `/sbin/init` shim (built into rootfs.vhdx)
//! takes over PID 1 after switch_root, learns about every share via
//! `MountFuse` ops on the init vsock channel, and serves shell sessions
//! over the init channel.

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

/// Allocate a unique vsock port for the per-session FUSE-over-vsock
/// listener. Uses a high range (like `alloc_session_init_port`) to avoid
/// collision with well-known ports. The port is registered in the HCS
/// HvSocket service table so the guest can connect to it.
pub fn alloc_fuse_port() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // 0x50000000 .. 0x50FFFFFF — distinct from init_port (0x40xxxxxx).
    0x5000_0000 | (n & 0x00FF_FFFF)
}

/// Build the HvSocket service GUID for a given vsock port.
/// Hyper-V's mapping: GUID = `XXXXXXXX-FACB-11E6-BD58-64006A7986D3`,
/// where `XXXXXXXX` is the vsock port in big-endian hex.
pub fn hvsock_service_id(port: u32) -> String {
    format!("{:08X}-FACB-11E6-BD58-64006A7986D3", port)
}

/// Build an HCS Schema 2.x JSON config for **session mode** with
/// FUSE-over-vsock user mounts and an explicit rootfs VHDX. The rootfs
/// is mounted on SCSI controller 0 attachment 0 (`/dev/sda`) read-write
/// — persistent vs ephemeral lifecycle is managed at a higher layer
/// (`vhdx_pool`).
///
/// The kernel cmdline carries `tokimo.init_port=` and
/// `tokimo.fuse_port=`. The guest init learns about every share through
/// `MountFuse` ops on the init vsock channel after `Hello`.
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
    memory_mb: u64,
    cpu_count: usize,
    init_port: u32,
    fuse_port: u32,
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

    let mut devices = serde_json::Map::new();
    devices.insert("Scsi".into(), scsi);

    // Register HvSocket service GUIDs for init control, FUSE listener,
    // and optionally netstack. The guest connects to these from inside
    // the VM via vsock.
    let mut svc_table = serde_json::Map::new();
    let entry = serde_json::json!({
        "BindSecurityDescriptor":    "D:(A;;GA;;;WD)",
        "ConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
        "AllowWildcardBinds": true
    });
    svc_table.insert(hvsock_service_id(init_port), entry.clone());
    svc_table.insert(hvsock_service_id(fuse_port), entry);
    if let Some(p) = netstack_port {
        let net_entry = serde_json::json!({
            "BindSecurityDescriptor":    "D:(A;;GA;;;WD)",
            "ConnectSecurityDescriptor": "D:(A;;GA;;;WD)",
            "AllowWildcardBinds": true
        });
        svc_table.insert(hvsock_service_id(p), net_entry);
    }
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
             tokimo.fuse_port={fuse_port} \
             tokimo.net=netstack tokimo.netstack_port={p}"
        ),
        None => format!(
            "console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw \
             tokimo.session=1 tokimo.init_port={init_port} \
             tokimo.fuse_port={fuse_port}"
        ),
    };

    // 0 = no limit: omit the field so HCS applies no constraint.
    let mut topology = serde_json::Map::new();
    if memory_mb > 0 {
        // Dynamic backing: VM only consumes physical RAM as the guest actually
        // touches pages. Mirrors WSL2 / hcsshim defaults. AllowOvercommit must
        // be true for EnableDeferredCommit (HCS rejects otherwise).
        // Field reference: microsoft/hcsshim internal/hcs/schema2/virtual_machine_memory.go
        topology.insert(
            "Memory".into(),
            serde_json::json!({
                "SizeInMB": memory_mb,
                "AllowOvercommit": true,
                "EnableDeferredCommit": true,
                "EnableHotHint": true,
                "EnableColdHint": true,
                "EnableColdDiscardHint": true,
            }),
        );
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
    fn v2_schema_and_cmdline() {
        let (k, i, rootfs) = dummy_paths();
        let s = build_session_v2_ex("id", &k, &i, &rootfs, 1024, 2, 0x4000_0001, 0x5000_0001, None);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        // SCSI carries the persistent rootfs path.
        assert_eq!(
            v["VirtualMachine"]["Devices"]["Scsi"]["0"]["Attachments"]["0"]["Path"],
            r"C:\persist.vhdx"
        );

        // No Plan9 device.
        assert!(
            v["VirtualMachine"]["Devices"].get("Plan9").is_none(),
            "Plan9 must not be present"
        );

        // HvSocket service table registers init + fuse ports.
        let table = v["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
            .as_object()
            .unwrap();
        assert!(table.contains_key(&hvsock_service_id(0x4000_0001)));
        assert!(table.contains_key(&hvsock_service_id(0x5000_0001)));

        let cmdline = v["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"]
            .as_str()
            .unwrap();
        assert!(cmdline.contains("tokimo.init_port=1073741825"));
        assert!(cmdline.contains("tokimo.fuse_port=1342177281"));
        assert!(cmdline.contains("root=/dev/sda"));
        assert!(cmdline.contains("rootfstype=ext4"));
        assert!(cmdline.contains("console=ttyS1"));
    }

    #[test]
    fn v2_topology_and_comports() {
        let (k, i, rootfs) = dummy_paths();
        let s = build_session_v2_ex("vm-foo", &k, &i, &rootfs, 4096, 8, 0x4000_00AB, 0x5000_00AB, None);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        assert_eq!(v["VirtualMachine"]["ComputeTopology"]["Memory"]["SizeInMB"], 4096);
        assert_eq!(v["VirtualMachine"]["ComputeTopology"]["Processor"]["Count"], 8);

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
        let s = build_session_v2_ex("id", &k, &i, &rootfs, 1024, 2, 0x4000_0002, 0x5000_0002, Some(port));
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
    fn alloc_fuse_port_is_in_range_and_unique() {
        let a = alloc_fuse_port();
        let b = alloc_fuse_port();
        assert_ne!(a, b);
        for p in [a, b] {
            assert_eq!(p & 0xFF00_0000, 0x5000_0000, "fuse port {p:#x} out of range");
        }
    }

    #[test]
    fn port_allocators_distinct_ranges() {
        let init = alloc_session_init_port();
        let fuse = alloc_fuse_port();
        assert_ne!(init, fuse);
        assert_eq!(init & 0xFF00_0000, 0x4000_0000);
        assert_eq!(fuse & 0xFF00_0000, 0x5000_0000);
    }
}
