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

    /// Boot a Linux VM in **session** mode. After the response
    /// (`SessionOpened`) the client pipe enters tunnel mode: every byte
    /// written by the client is forwarded raw to the guest's COM1 (which
    /// is the data channel for `tokimo-sandbox-init`'s init protocol),
    /// and every byte the guest writes to COM1 is forwarded back to the
    /// client. The VM is torn down when the client pipe disconnects.
    OpenSession {
        id: String,
        kernel_path: String,
        initrd_path: String,
        rootfs_dir: String,
        workspace_path: String,
        memory_mb: u64,
        cpu_count: usize,
        #[serde(default = "default_network")]
        network: SvcNetwork,
    },
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
    /// transparent byte tunnel to/from the guest's COM1 (init protocol).
    #[serde(rename = "SessionOpened")]
    SessionOpened { id: String },
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
                rootfs_dir,
                network,
                ..
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
