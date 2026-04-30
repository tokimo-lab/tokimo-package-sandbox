//! Client for the tokimo-sandbox-svc named pipe.
//!
//! Opens `\\.\pipe\tokimo-sandbox-svc`, sends one length-prefixed JSON
//! request, reads one length-prefixed JSON response, closes the pipe.
//!
//! The service is expected to be running already. If the pipe is missing
//! we return a clear error instead of trying to auto-elevate via UAC; the
//! recommended install path is the MSIX in `packaging/windows/`.

#![cfg(target_os = "windows")]

use std::path::Path;
use std::time::Duration;

use windows::Win32::Foundation::{ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, GetLastError};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::HSTRING;

use crate::{Error, ExecutionResult, Result};

use super::ov_pipe::OvPipe;
use super::protocol::{SvcNetwork, SvcRequest, SvcResponse};

const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";
const CONNECT_TIMEOUT_MS: u32 = 5_000;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) fn exec_vm(
    kernel_path: &Path,
    initrd_path: &Path,
    rootfs_dir: &Path,
    workspace_path: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
    network: SvcNetwork,
) -> Result<ExecutionResult> {
    let mut pipe = open_pipe().map_err(|e| {
        Error::exec(format!(
            "tokimo-sandbox-svc not reachable on {PIPE_NAME}: {e}. \
             Install the MSIX from packaging/windows/, or run \
             `tokimo-sandbox-svc.exe --install` once.",
        ))
    })?;

    let id = format!("svc-{}-{}", std::process::id(), next_req_id());
    let req = SvcRequest::ExecVm {
        id: id.clone(),
        kernel_path: kernel_path.to_string_lossy().into_owned(),
        initrd_path: initrd_path.to_string_lossy().into_owned(),
        rootfs_dir: rootfs_dir.to_string_lossy().into_owned(),
        workspace_path: workspace_path.to_string_lossy().into_owned(),
        cmd_b64: cmd_b64.to_string(),
        memory_mb,
        cpu_count,
        network,
    };

    super::protocol::send_request(&mut pipe, &req).map_err(|e| Error::exec(format!("send request: {e}")))?;
    let resp = super::protocol::recv_response(&mut pipe).map_err(|e| Error::exec(format!("recv response: {e}")))?;

    match resp {
        SvcResponse::ExecVmResult { result, .. } => Ok(ExecutionResult {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.exit_code,
            timed_out: result.timed_out,
            oom_killed: false,
        }),
        SvcResponse::Error { error, .. } => Err(Error::exec(format!(
            "service error [{}]: {}",
            error.code, error.message
        ))),
        SvcResponse::Pong { .. } => Err(Error::exec("unexpected Pong response")),
        SvcResponse::SessionOpened { .. } => Err(Error::exec("unexpected SessionOpened on ExecVm path")),
    }
}

pub(crate) fn is_service_available() -> bool {
    let name = HSTRING::from(PIPE_NAME);
    unsafe { WaitNamedPipeW(&name, 500).as_bool() }
}

/// Open a session VM. Sends `OpenSession` (V2: `RootfsSpec` + multi
/// `ShareSpec`), reads `SessionOpened`, then returns:
///   - the underlying overlapped pipe `OvPipe` — the service has now
///     flipped it into transparent tunnel mode and any further bytes
///     flow directly to/from the guest's init HvSocket service;
///   - the `init_port` the service registered for the init control
///     channel (informational; encoded in the service GUID);
///   - `share_ports`, parallel to the input `shares` slice — the guest
///     will dial these from inside the VM in response to a
///     `MountManifest` op sent over the init protocol.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_session(
    kernel_path: &Path,
    initrd_path: &Path,
    rootfs: super::protocol::RootfsSpec,
    shares: Vec<super::protocol::ShareSpec>,
    memory_mb: u64,
    cpu_count: usize,
    network: SvcNetwork,
) -> Result<(OvPipe, u32, Vec<u32>)> {
    let mut pipe = open_pipe().map_err(|e| {
        Error::exec(format!(
            "tokimo-sandbox-svc not reachable on {PIPE_NAME}: {e}. \
             Install the MSIX from packaging/windows/, or run \
             `tokimo-sandbox-svc.exe --install` once.",
        ))
    })?;

    let id = format!("svc-{}-{}", std::process::id(), next_req_id());
    let req = SvcRequest::OpenSession {
        id: id.clone(),
        protocol_version: super::protocol::WIRE_PROTOCOL_VERSION,
        kernel_path: kernel_path.to_string_lossy().into_owned(),
        initrd_path: initrd_path.to_string_lossy().into_owned(),
        rootfs,
        shares,
        memory_mb,
        cpu_count,
        network,
    };

    super::protocol::send_request(&mut pipe, &req).map_err(|e| Error::exec(format!("send OpenSession: {e}")))?;
    let resp =
        super::protocol::recv_response(&mut pipe).map_err(|e| Error::exec(format!("recv SessionOpened: {e}")))?;
    match resp {
        SvcResponse::SessionOpened {
            init_port, share_ports, ..
        } => Ok((pipe, init_port, share_ports)),
        SvcResponse::Error { error, .. } => {
            // Translate well-known structured codes to the typed library error.
            if error.code == "session_busy" || error.code == "persistent_busy" {
                return Err(Error::SessionAlreadyActive);
            }
            Err(Error::exec(format!(
                "service error [{}]: {}",
                error.code, error.message
            )))
        }
        other => Err(Error::exec(format!("unexpected response: {other:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Pipe I/O
// ---------------------------------------------------------------------------

/// Open the pipe with FILE_FLAG_OVERLAPPED. Retries on `ERROR_PIPE_BUSY`
/// with backoff — tests run in parallel and can race for pipe instances
/// even after `WaitNamedPipeW` returns.
fn open_pipe() -> std::io::Result<OvPipe> {
    let name = HSTRING::from(PIPE_NAME);
    let mut attempts = 0;

    loop {
        let waited = unsafe { WaitNamedPipeW(&name, CONNECT_TIMEOUT_MS) };
        if !waited.as_bool() {
            let code = unsafe { GetLastError() }.0;
            return Err(std::io::Error::from_raw_os_error(code as i32));
        }

        match unsafe {
            CreateFileW(
                &name,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                Some(std::ptr::null::<SECURITY_ATTRIBUTES>()),
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OVERLAPPED.0),
                None,
            )
        } {
            Ok(handle) => return OvPipe::from_handle(handle),
            Err(e) if e.code() == ERROR_PIPE_BUSY.to_hresult() => {
                attempts += 1;
                if attempts >= 10 {
                    return Err(std::io::Error::from_raw_os_error(ERROR_PIPE_BUSY.0 as i32));
                }
                std::thread::sleep(Duration::from_millis(50 * attempts));
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e.code().0)),
        }
    }
}

fn next_req_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
