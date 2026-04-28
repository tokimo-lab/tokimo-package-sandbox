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
        rootfs_path: String,
        cmd_b64: String,
        memory_mb: u64,
        cpu_count: usize,
    },
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
    #[serde(rename = "Error")]
    Error { id: String, error: SvcError },
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Read one length-prefixed JSON frame from a reader. Blocks until the full
/// payload is received. Returns the raw UTF-8 bytes.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    // Sanity: reject frames larger than 16 MiB.
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

/// Write one length-prefixed JSON frame to a writer.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Serialize a request to a buffer and write it as a frame.
pub fn send_request<W: Write>(w: &mut W, req: &SvcRequest) -> io::Result<()> {
    let json =
        serde_json::to_vec(req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {e}")))?;
    write_frame(w, &json)
}

/// Read a frame and deserialize it as a response.
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
    fn test_exec_vm_roundtrip() {
        let req = SvcRequest::ExecVm {
            id: "vm-1".into(),
            kernel_path: "C:\\\\Users\\\\test\\\\.tokimo\\\\kernel\\\\vmlinuz".into(),
            initrd_path: "C:\\\\Users\\\\test\\\\.tokimo\\\\initrd.img".into(),
            rootfs_path: "C:\\\\Users\\\\test\\\\.tokimo\\\\rootfs".into(),
            cmd_b64: "ZWNobyBoZWxsbw==".into(),
            memory_mb: 512,
            cpu_count: 2,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SvcRequest = serde_json::from_slice(&json).unwrap();
        match parsed {
            SvcRequest::ExecVm {
                cmd_b64,
                memory_mb,
                cpu_count,
                ..
            } => {
                assert_eq!(cmd_b64, "ZWNobyBoZWxsbw==");
                assert_eq!(memory_mb, 512);
                assert_eq!(cpu_count, 2);
            }
            _ => panic!("expected ExecVm"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = SvcResponse::ExecVmResult {
            id: "vm-1".into(),
            result: ExecVmResult {
                stdout: "hello".into(),
                stderr: String::new(),
                exit_code: 0,
                timed_out: false,
            },
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: SvcResponse = serde_json::from_slice(&json).unwrap();
        match parsed {
            SvcResponse::ExecVmResult { id, result } => {
                assert_eq!(id, "vm-1");
                assert_eq!(result.stdout, "hello");
                assert_eq!(result.exit_code, 0);
            }
            _ => panic!("expected ExecVmResult"),
        }
    }

    #[test]
    fn test_error_response_roundtrip() {
        let resp = SvcResponse::Error {
            id: "vm-1".into(),
            error: SvcError {
                code: "hcs_error".into(),
                message: "HcsCreateComputeSystem failed: HRESULT 0x8037011B".into(),
            },
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: SvcResponse = serde_json::from_slice(&json).unwrap();
        match parsed {
            SvcResponse::Error { id, error } => {
                assert_eq!(id, "vm-1");
                assert_eq!(error.code, "hcs_error");
            }
            _ => panic!("expected Error"),
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
        // Create a fake frame claiming 20 MiB.
        let len: u32 = 20 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        // The read will fail because there aren't enough bytes.
        let result = read_frame(&mut &buf[..]);
        assert!(result.is_err());
    }
}
