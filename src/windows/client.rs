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
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::HSTRING;

use crate::{Error, ExecutionResult, Result};

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
    rootfs_vhdx: Option<&Path>,
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
        rootfs_vhdx: rootfs_vhdx.map(|p| p.to_string_lossy().into_owned()),
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
    }
}

pub(crate) fn is_service_available() -> bool {
    let name = HSTRING::from(PIPE_NAME);
    unsafe { WaitNamedPipeW(&name, 500).as_bool() }
}

// ---------------------------------------------------------------------------
// Pipe I/O
// ---------------------------------------------------------------------------

/// Open the pipe as a `std::fs::File`. Pipe handles in Windows behave like
/// file handles: `Read`/`Write` Just Work. We retry once on `ERROR_PIPE_BUSY`
/// after waiting up to `CONNECT_TIMEOUT_MS`.
fn open_pipe() -> std::io::Result<std::fs::File> {
    let name = HSTRING::from(PIPE_NAME);

    // Wait until the server has an available instance.
    let waited = unsafe { WaitNamedPipeW(&name, CONNECT_TIMEOUT_MS) };
    if !waited.as_bool() {
        let code = unsafe { GetLastError() }.0;
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // Open it. We use CreateFileW directly (rather than OpenOptions) so we
    // can pass exact share/create flags.
    let handle = unsafe {
        CreateFileW(
            &name,
            (GENERIC_READ.0 | GENERIC_WRITE.0) as u32,
            FILE_SHARE_NONE,
            Some(std::ptr::null::<SECURITY_ATTRIBUTES>()),
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

    // ERROR_PIPE_BUSY shouldn't happen after WaitNamedPipeW returned OK, but
    // handle it defensively.
    let raw = handle.0 as isize;
    if raw == -1 {
        let last = unsafe { GetLastError() };
        if last == ERROR_PIPE_BUSY {
            std::thread::sleep(Duration::from_millis(50));
            return Err(std::io::Error::from_raw_os_error(ERROR_PIPE_BUSY.0 as i32));
        }
        return Err(std::io::Error::from_raw_os_error(last.0 as i32));
    }

    // Adopt the HANDLE as a std::fs::File. Note: File takes ownership and
    // will close it on drop. From-raw-handle is the documented way.
    use std::os::windows::io::FromRawHandle;
    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as _) })
}

fn next_req_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
