//! Client for the tokimo-sandbox-svc named pipe.
//!
//! Connects to `\\.\pipe\tokimo-sandbox-svc`, sends VM execution requests,
//! and reads responses. On first pipe-not-found, attempts auto-install via UAC.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::{Error, ExecutionResult, Result};

use super::protocol::SvcRequest;
use super::protocol::SvcResponse;

// kernel32 I/O primitives (avoid windows-sys module path churn)
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut c_void,
    ) -> *mut c_void;

    fn ReadFile(
        hFile: *mut c_void,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;

    fn WriteFile(
        hFile: *mut c_void,
        lpBuffer: *const c_void,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;

    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn ShellExecuteW(
        hwnd: *mut c_void,
        lpOperation: *const u16,
        lpFile: *const u16,
        lpParameters: *const u16,
        lpDirectory: *const u16,
        nShowCmd: i32,
    ) -> *mut c_void;
}

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE_VALUE: *mut c_void = usize::MAX as *mut c_void;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Try to execute a command via the SYSTEM service.
pub(crate) fn exec_vm(
    kernel_path: &Path,
    initrd_path: &Path,
    rootfs_path: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> Result<ExecutionResult> {
    let pipe_name = r"\\.\pipe\tokimo-sandbox-svc";

    match connect_and_exec(
        kernel_path,
        initrd_path,
        rootfs_path,
        cmd_b64,
        memory_mb,
        cpu_count,
        pipe_name,
    ) {
        Ok(r) => return Ok(r),
        Err(ServiceError::PipeNotFound) => {
            auto_install_service();
            match connect_and_exec(
                kernel_path,
                initrd_path,
                rootfs_path,
                cmd_b64,
                memory_mb,
                cpu_count,
                pipe_name,
            ) {
                Ok(r) => return Ok(r),
                Err(e) => Err(Error::exec(format!("SERVICE backend error: {e}"))),
            }
        }
        Err(e) => Err(Error::exec(format!("SERVICE backend error: {e}"))),
    }
}

/// Check if the service pipe is available.
pub(crate) fn is_service_available() -> bool {
    let pipe_name_w: Vec<u16> = r"\\.\pipe\tokimo-sandbox-svc\0".encode_utf16().collect();
    unsafe { windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_w.as_ptr(), 500) != 0 }
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ServiceError {
    PipeNotFound,
    Io(std::io::Error),
    Protocol(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PipeNotFound => write!(f, "service pipe not found"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        let raw = e.raw_os_error().unwrap_or(0) as u32;
        if raw == 2 || raw == 3 {
            return Self::PipeNotFound;
        }
        Self::Io(e)
    }
}

fn connect_and_exec(
    kernel_path: &Path,
    initrd_path: &Path,
    rootfs_path: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
    pipe_name: &str,
) -> std::result::Result<ExecutionResult, ServiceError> {
    let pipe_name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    // Wait for the pipe.
    let available = unsafe { windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_w.as_ptr(), 3000) };
    if available == 0 {
        return Err(ServiceError::PipeNotFound);
    }

    // Open the pipe.
    let handle = unsafe {
        CreateFileW(
            pipe_name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(ServiceError::PipeNotFound);
    }

    // Build request.
    let id = format!(
        "svc-{}-{}",
        std::process::id(),
        REQ_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let req = SvcRequest::ExecVm {
        id,
        kernel_path: kernel_path.to_string_lossy().into_owned(),
        initrd_path: initrd_path.to_string_lossy().into_owned(),
        rootfs_path: rootfs_path.to_string_lossy().into_owned(),
        cmd_b64: cmd_b64.to_string(),
        memory_mb,
        cpu_count,
    };

    let json = serde_json::to_vec(&req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize: {e}")))?;

    // Send length prefix + payload.
    let len = json.len() as u32;
    let mut written: u32 = 0;
    if unsafe {
        WriteFile(
            handle,
            (&len as *const u32) as *const c_void,
            4,
            &mut written,
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe { CloseHandle(handle) };
        return Err(ServiceError::from(std::io::Error::last_os_error()));
    }
    if unsafe {
        WriteFile(
            handle,
            json.as_ptr() as *const c_void,
            len,
            &mut written,
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe { CloseHandle(handle) };
        return Err(ServiceError::from(std::io::Error::last_os_error()));
    }

    // Read response length + payload.
    let mut len_buf = [0u8; 4];
    let mut bytes_read: u32 = 0;
    if unsafe {
        ReadFile(
            handle,
            len_buf.as_mut_ptr() as *mut c_void,
            4,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    } == 0
        || bytes_read != 4
    {
        unsafe { CloseHandle(handle) };
        return Err(ServiceError::Protocol("failed to read response length".into()));
    }

    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 16 * 1024 * 1024 {
        unsafe { CloseHandle(handle) };
        return Err(ServiceError::Protocol("response too large".into()));
    }

    let mut resp_payload = vec![0u8; resp_len];
    if unsafe {
        ReadFile(
            handle,
            resp_payload.as_mut_ptr() as *mut c_void,
            resp_len as u32,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    } == 0
        || bytes_read as usize != resp_len
    {
        unsafe { CloseHandle(handle) };
        return Err(ServiceError::Protocol("failed to read response body".into()));
    }
    unsafe { CloseHandle(handle) };

    let resp: SvcResponse =
        serde_json::from_slice(&resp_payload).map_err(|e| ServiceError::Protocol(format!("deserialize: {e}")))?;

    match resp {
        SvcResponse::ExecVmResult { result, .. } => Ok(ExecutionResult {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.exit_code,
            timed_out: result.timed_out,
            oom_killed: false,
        }),
        SvcResponse::Error { error, .. } => Err(ServiceError::Protocol(format!(
            "service error [{}]: {}",
            error.code, error.message
        ))),
        other => Err(ServiceError::Protocol(format!("unexpected response: {other:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Auto-install
// ---------------------------------------------------------------------------

static INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static REQ_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn auto_install_service() {
    if INSTALL_ATTEMPTED.swap(true, Ordering::Relaxed) {
        return;
    }

    let svc_path = match find_service_binary() {
        Some(p) => p,
        None => {
            tracing::warn!("tokimo-sandbox-svc.exe not found, cannot auto-install service");
            return;
        }
    };

    tracing::info!(
        svc = %svc_path.display(),
        "Attempting one-time service install via UAC..."
    );

    let svc_str: Vec<u16> = svc_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let install_arg: Vec<u16> = "--install\0".encode_utf16().collect();
    let runas: Vec<u16> = "runas\0".encode_utf16().collect();

    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            runas.as_ptr(),
            svc_str.as_ptr(),
            install_arg.as_ptr(),
            std::ptr::null(),
            0,
        )
    };

    let ret_val = ret as usize;
    if ret_val > 32 {
        tracing::info!("Service install UAC prompt shown. Waiting for service to start...");

        let deadline = Instant::now() + Duration::from_secs(30);
        let pipe_w: Vec<u16> = r"\\.\pipe\tokimo-sandbox-svc\0".encode_utf16().collect();
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(500));
            let avail = unsafe { windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_w.as_ptr(), 100) };
            if avail != 0 {
                tracing::info!("Service pipe now available");
                return;
            }
        }
        tracing::warn!("Service did not start within 30s after install");
    } else {
        tracing::warn!(
            "UAC elevation failed (ShellExecuteW returned {ret_val}). \
             Install manually: {} --install",
            svc_path.display()
        );
    }
}

fn find_service_binary() -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let pb = dir.join("tokimo-sandbox-svc.exe");
            if pb.exists() {
                return Some(pb);
            }
        }
    }
    None
}
