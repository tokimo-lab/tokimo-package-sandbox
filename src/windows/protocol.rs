//! Wire protocol for tokimo-sandbox-svc named pipe.
//!
//! Length-prefixed JSON frames:
//!   [4 bytes LE u32 payload length][UTF-8 JSON payload]
//!
//! The service handles one request per connection (synchronous RPC).

use std::io::{self, Read, Write};

// ---------------------------------------------------------------------------
// Frame types
// ---------------------------------------------------------------------------

/// Network policy as seen by the service. The host library translates the
/// richer `NetworkPolicy` enum into this on-the-wire form: anything beyond
/// the two simple cases is downgraded to `Blocked` on Windows because we
/// don't yet ship a gvisor-style netstack in the SYSTEM service.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SvcNetwork {
    /// No NIC is attached to the VM. Guest cannot reach anything.
    Blocked,
    /// Default Hyper-V NAT NIC is attached. Guest has full network access.
    AllowAll,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op")]
pub enum SvcRequest {
    /// Smoke test: verify service is alive.
    Ping { id: String },

    /// Boot a Linux VM and run a command.
    ExecVm {
        id: String,
        kernel_path: String,
        initrd_path: String,
        /// Host directory shared as Plan9 tag `rootshare` and used as the
        /// Debian rootfs (the guest does `switch_root` into it).
        rootfs_dir: String,
        /// Host directory shared as Plan9 tag `work`. The guest mounts it
        /// at `/mnt/work` inside the rootfs and writes `.vz_stdout`,
        /// `.vz_stderr`, `.vz_exit_code` here.
        workspace_path: String,
        cmd_b64: String,
        memory_mb: u64,
        cpu_count: usize,
        #[serde(default = "default_network")]
        network: SvcNetwork,
    },

    /// Boot a Linux VM in **session** mode.
    ///
    /// V2 (`protocol_version = 2`): the caller provides:
    ///   - `rootfs`: ephemeral or persistent rootfs VHDX policy
    ///   - `shares`: ordered list of host directories to expose as
    ///     Plan9-over-vsock shares; the first share is conventionally the
    ///     primary workspace mounted at `/mnt/work`.
    ///
    /// On success the service replies `SessionOpened { init_port,
    /// share_ports }`, then the named pipe enters tunnel mode and forwards
    /// raw bytes between the client and the guest's init control HvSocket.
    /// The guest dials each `share_ports[i]` itself in response to a
    /// `MountManifest` op carried over the init protocol.
    OpenSession {
        id: String,
        protocol_version: u32,
        kernel_path: String,
        initrd_path: String,
        rootfs: RootfsSpec,
        shares: Vec<ShareSpec>,
        memory_mb: u64,
        cpu_count: usize,
        #[serde(default = "default_network")]
        network: SvcNetwork,
    },
}

/// Wire protocol version negotiated at `OpenSession` time. Bumped on
/// breaking changes to the V2 schema.
pub const WIRE_PROTOCOL_VERSION: u32 = 2;

/// Caller-controlled rootfs policy. Persistent rootfs lets a single
/// caller-owned VHDX file survive across sessions; ephemeral clones the
/// template into a per-session temporary that is deleted on teardown.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum RootfsSpec {
    Ephemeral { template: String },
    Persistent { template: String, target: String },
}

/// One Plan9 share to expose to the guest. Each share lands on its own
/// vsock port (allocated by the service) and the guest mounts it at
/// `guest_path` after the init `MountManifest` op completes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ShareSpec {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
    pub name: String,
}

fn default_network() -> SvcNetwork {
    SvcNetwork::Blocked
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SvcError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExecVmResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum SvcResponse {
    #[serde(rename = "Pong")]
    Pong { id: String, version: String },
    #[serde(rename = "ExecVmResult")]
    ExecVmResult {
        id: String,
        #[serde(flatten)]
        result: ExecVmResult,
    },
    /// Successful response to `OpenSession`. The client pipe is now a
    /// transparent byte tunnel to/from the guest's init HvSocket service.
    /// `init_port` is the vsock port for the init control channel.
    /// `share_ports[i]` matches `OpenSession.shares[i]`.
    #[serde(rename = "SessionOpened")]
    SessionOpened {
        id: String,
        protocol_version: u32,
        init_port: u32,
        share_ports: Vec<u32>,
    },
    #[serde(rename = "Error")]
    Error { id: String, error: SvcError },
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

pub fn send_request<W: Write>(w: &mut W, req: &SvcRequest) -> io::Result<()> {
    let json =
        serde_json::to_vec(req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {e}")))?;
    write_frame(w, &json)
}

pub fn recv_response<R: Read>(r: &mut R) -> io::Result<SvcResponse> {
    let payload = read_frame(r)?;
    serde_json::from_slice(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("deserialize: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_roundtrip() {
        let req = SvcRequest::Ping { id: "test-1".into() };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SvcRequest = serde_json::from_slice(&json).unwrap();
        match parsed {
            SvcRequest::Ping { id } => assert_eq!(id, "test-1"),
            _ => panic!("expected Ping"),
        }
    }

    #[test]
    fn test_exec_vm_roundtrip_with_rootfs_dir() {
        let req = SvcRequest::ExecVm {
            id: "vm-1".into(),
            kernel_path: r"C:\tokimo\vmlinuz".into(),
            initrd_path: r"C:\tokimo\initrd.img".into(),
            rootfs_dir: r"C:\tokimo\rootfs".into(),
            workspace_path: r"C:\Users\me\work".into(),
            cmd_b64: "ZWNobyBoZWxsbw==".into(),
            memory_mb: 512,
            cpu_count: 2,
            network: SvcNetwork::Blocked,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SvcRequest = serde_json::from_slice(&json).unwrap();
        match parsed {
            SvcRequest::ExecVm {
                rootfs_dir, network, ..
            } => {
                assert_eq!(rootfs_dir, r"C:\tokimo\rootfs");
                assert_eq!(network, SvcNetwork::Blocked);
            }
            _ => panic!("expected ExecVm"),
        }
    }

    #[test]
    fn test_exec_vm_legacy_default_network() {
        let json = br#"{"op":"ExecVm","id":"x","kernel_path":"k","initrd_path":"i","rootfs_dir":"r","workspace_path":"w","cmd_b64":"","memory_mb":1,"cpu_count":1}"#;
        let parsed: SvcRequest = serde_json::from_slice(json).unwrap();
        match parsed {
            SvcRequest::ExecVm { network, .. } => assert_eq!(network, SvcNetwork::Blocked),
            _ => panic!("expected ExecVm"),
        }
    }

    #[test]
    fn test_open_session_v2_roundtrip() {
        let req = SvcRequest::OpenSession {
            id: "sess-1".into(),
            protocol_version: WIRE_PROTOCOL_VERSION,
            kernel_path: r"C:\vmlinuz".into(),
            initrd_path: r"C:\initrd.img".into(),
            rootfs: RootfsSpec::Ephemeral {
                template: r"C:\rootfs.vhdx".into(),
            },
            shares: vec![
                ShareSpec {
                    host_path: r"C:\work".into(),
                    guest_path: "/mnt/work".into(),
                    read_only: false,
                    name: "s0".into(),
                },
                ShareSpec {
                    host_path: r"C:\readonly".into(),
                    guest_path: "/mnt/ro".into(),
                    read_only: true,
                    name: "s1".into(),
                },
            ],
            memory_mb: 2048,
            cpu_count: 2,
            network: SvcNetwork::Blocked,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SvcRequest = serde_json::from_slice(&json).unwrap();
        match parsed {
            SvcRequest::OpenSession {
                shares,
                rootfs,
                protocol_version,
                ..
            } => {
                assert_eq!(protocol_version, 2);
                assert_eq!(shares.len(), 2);
                assert!(matches!(rootfs, RootfsSpec::Ephemeral { .. }));
                assert!(shares[1].read_only);
            }
            _ => panic!("expected OpenSession"),
        }
    }

    #[test]
    fn test_persistent_rootfs_serde() {
        let s = RootfsSpec::Persistent {
            template: r"C:\template.vhdx".into(),
            target: r"C:\caller\rootfs.vhdx".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: RootfsSpec = serde_json::from_str(&j).unwrap();
        assert_eq!(s, p);
    }

    #[test]
    fn test_session_opened_v2() {
        let r = SvcResponse::SessionOpened {
            id: "x".into(),
            protocol_version: WIRE_PROTOCOL_VERSION,
            init_port: 0x4000_0001,
            share_ports: vec![0x4100_0001, 0x4100_0002],
        };
        let j = serde_json::to_vec(&r).unwrap();
        let p: SvcResponse = serde_json::from_slice(&j).unwrap();
        match p {
            SvcResponse::SessionOpened {
                share_ports, init_port, ..
            } => {
                assert_eq!(init_port, 0x4000_0001);
                assert_eq!(share_ports.len(), 2);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_frame_read_write() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).unwrap();
        let read_back = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn test_frame_large_rejected() {
        let len: u32 = 20 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        let result = read_frame(&mut &buf[..]);
        assert!(result.is_err());
    }
}
