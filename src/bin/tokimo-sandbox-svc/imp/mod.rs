//! Windows-only implementation of the SYSTEM service.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HWND, INVALID_HANDLE_VALUE, LocalFree, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION,
    WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use tokimo_package_sandbox::svc_protocol::{
    ExecVmResult, SvcError, SvcNetwork, SvcRequest, SvcResponse,
};
use tokimo_package_sandbox::canonicalize_safe;

mod hcs;
mod vmconfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SERVICE_NAME: &str = "TokimoSandboxSvc";
const SERVICE_DISPLAY: &str = "Tokimo Sandbox Service";
const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";

/// SDDL for the named pipe.
///
/// `O:SY` owner = LocalSystem
/// `G:SY` group = LocalSystem
/// `D:` DACL:
///   * `(A;;GA;;;SY)` - LocalSystem: GENERIC_ALL
///   * `(A;;0x12019b;;;IU)` - Interactive Users: read|write|sync without
///     delete/changeperms (FILE_GENERIC_READ | FILE_GENERIC_WRITE).
///
/// `IU` (Interactive Users) is the well-known SID `S-1-5-4`. It is **not**
/// the same as `BU` (Built-in Users, `S-1-5-32-545`); BU includes
/// `NETWORK SERVICE`, `LOCAL SERVICE`, and (depending on policy) Guest.
const PIPE_SDDL: &str = "O:SYG:SYD:(A;;GA;;;SY)(A;;0x12019b;;;IU)";

const VERSION: &str = env!("CARGO_PKG_VERSION");

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => return install_service(),
            "--uninstall" => return uninstall_service(),
            "--console" => return run_console(),
            "-h" | "--help" => {
                println!("tokimo-sandbox-svc v{VERSION}");
                println!("Usage: tokimo-sandbox-svc [--install|--uninstall|--console]");
                return;
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(2);
            }
        }
    }

    // Default: SCM started us as a service.
    if let Err(e) = windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("service_dispatcher::start failed: {e}");
        eprintln!("If you meant to run interactively, use --console");
        std::process::exit(1);
    }
}

fn run_console() {
    println!("Tokimo Sandbox Service v{VERSION} (console mode)");
    println!("Pipe: {PIPE_NAME}");
    println!("Caller verification: {}", if verify_caller_required() { "ENFORCED" } else { "log-only" });
    println!("Waiting for connections... (Ctrl+C to stop)");
    pipe_server_loop();
}

// ---------------------------------------------------------------------------
// SCM service
// ---------------------------------------------------------------------------

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_as_service() {
        eprintln!("service error: {e}");
    }
}

fn run_as_service() -> windows_service::Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                SHUTDOWN.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    pipe_server_loop();

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

fn install_service() {
    let exe = std::env::current_exe().expect("current_exe");
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("OpenSCManager failed: {e}");
            std::process::exit(1);
        }
    };

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START) {
        Ok(svc) => {
            // Best-effort: delayed auto-start so we boot only after Hyper-V
            // host services are up.
            let _ = svc.set_delayed_auto_start(true);
            if let Err(e) = svc.start::<&str>(&[]) {
                eprintln!("StartService failed (the service is still installed): {e}");
            } else {
                println!("Service installed and started: {SERVICE_NAME}");
            }
        }
        Err(e) => {
            // SERVICE_EXISTS is OK.
            let msg = e.to_string();
            if msg.contains("1073") || msg.to_lowercase().contains("exist") {
                println!("Service already installed: {SERVICE_NAME}");
            } else {
                eprintln!("CreateService failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn uninstall_service() {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("OpenSCManager failed: {e}");
            std::process::exit(1);
        }
    };

    let svc = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("1060") || msg.to_lowercase().contains("does not exist") {
                println!("Service not installed: {SERVICE_NAME}");
                return;
            }
            eprintln!("OpenService failed: {e}");
            std::process::exit(1);
        }
    };

    if let Ok(status) = svc.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            // Wait briefly.
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(200));
                if matches!(svc.query_status().map(|s| s.current_state), Ok(ServiceState::Stopped)) {
                    break;
                }
            }
        }
    }

    if let Err(e) = svc.delete() {
        eprintln!("DeleteService failed: {e}");
        std::process::exit(1);
    }
    println!("Service uninstalled: {SERVICE_NAME}");
}

// ---------------------------------------------------------------------------
// Pipe server
// ---------------------------------------------------------------------------

/// Holder that frees the security descriptor on drop.
struct SdGuard(PSECURITY_DESCRIPTOR);
impl Drop for SdGuard {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn build_security_attributes() -> std::io::Result<(SECURITY_ATTRIBUTES, SdGuard)> {
    let sddl = HSTRING::from(PIPE_SDDL);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    Ok((attrs, SdGuard(sd)))
}

fn pipe_server_loop() {
    let (mut sa, _sd_guard) = match build_security_attributes() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to build pipe SDDL: {e}");
            return;
        }
    };

    let pipe_name = HSTRING::from(PIPE_NAME);

    eprintln!("[svc] listening on {PIPE_NAME} (v{VERSION})");
    if verify_caller_required() {
        eprintln!("[svc] caller signature verification: ENFORCED");
    } else {
        eprintln!(
            "[svc] caller signature verification: log-only \
             (set TOKIMO_VERIFY_CALLER=1 or HKLM\\SOFTWARE\\Tokimo\\SandboxSvc\\VerifyCaller=1 to enforce)"
        );
    }

    while !SHUTDOWN.load(Ordering::Relaxed) {
        let pipe = unsafe {
            CreateNamedPipeW(
                &pipe_name,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                Some(&mut sa as *mut _),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            eprintln!("[svc] CreateNamedPipeW failed: {:?}", unsafe { GetLastError() });
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }

        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if connected.is_err() {
            // ERROR_PIPE_CONNECTED (535) means the client connected between
            // CreateNamedPipe and ConnectNamedPipe. That's fine.
            let last = unsafe { GetLastError() }.0;
            if last != 535 {
                let _ = unsafe { CloseHandle(pipe) };
                continue;
            }
        }

        // Hand the pipe to a worker thread. We carry the raw pointer as a
        // `usize` to side-step `HANDLE`'s lack of `Send` — there is exactly
        // one owner at any time.
        let pipe_ptr = pipe.0 as usize;
        std::thread::spawn(move || {
            handle_client(HANDLE(pipe_ptr as *mut _));
        });
    }
}

// ---------------------------------------------------------------------------
// Client handling
// ---------------------------------------------------------------------------

fn handle_client(pipe: HANDLE) {
    // Caller identity check — log always; reject if enforced.
    let caller = caller_image_path(pipe);
    match &caller {
        Some(p) => eprintln!("[svc] client connected: {}", p.display()),
        None => eprintln!("[svc] client connected: <unknown caller>"),
    }

    if verify_caller_required() {
        match caller.as_deref().and_then(safe_canon_or_log) {
            Some(canon) => {
                if let Err(why) = verify_authenticode(&canon) {
                    eprintln!("[svc] REJECT unsigned/untrusted caller {}: {why}", canon.display());
                    let _ = send_error_raw(pipe, "", "unauthorized", "caller not trusted");
                    disconnect(pipe);
                    return;
                }
            }
            None => {
                eprintln!("[svc] REJECT caller: could not resolve image path");
                let _ = send_error_raw(pipe, "", "unauthorized", "caller image not resolvable");
                disconnect(pipe);
                return;
            }
        }
    }

    let request = match read_request(pipe) {
        Ok(r) => r,
        Err(e) => {
            let _ = send_error_raw(pipe, "", "bad_request", &format!("read: {e}"));
            disconnect(pipe);
            return;
        }
    };

    match request {
        SvcRequest::Ping { id } => {
            let _ = send_response_raw(
                pipe,
                &SvcResponse::Pong {
                    id,
                    version: VERSION.to_string(),
                },
            );
        }
        SvcRequest::ExecVm {
            id,
            kernel_path,
            initrd_path,
            rootfs_vhdx,
            workspace_path,
            cmd_b64,
            memory_mb,
            cpu_count,
            network,
        } => {
            handle_exec_vm(
                pipe,
                id,
                &kernel_path,
                &initrd_path,
                rootfs_vhdx.as_deref(),
                &workspace_path,
                &cmd_b64,
                memory_mb,
                cpu_count,
                network,
            );
        }
    }

    disconnect(pipe);
}

fn disconnect(pipe: HANDLE) {
    unsafe {
        let _ = FlushFileBuffers(pipe);
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
}

fn safe_canon_or_log(p: &Path) -> Option<PathBuf> {
    match canonicalize_safe(p) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("[svc] path rejected ({}): {e}", p.display());
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ExecVm
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn handle_exec_vm(
    pipe: HANDLE,
    id: String,
    kernel_path: &str,
    initrd_path: &str,
    rootfs_vhdx: Option<&str>,
    workspace_path: &str,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
    network: SvcNetwork,
) {
    // Validate every path. canonicalize_safe rejects symlinks/junctions
    // and multi-hardlink files.
    let kernel = match canonicalize_safe(Path::new(kernel_path)) {
        Ok(p) => p,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "bad_path", &format!("kernel: {e}"));
            return;
        }
    };
    let initrd = match canonicalize_safe(Path::new(initrd_path)) {
        Ok(p) => p,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "bad_path", &format!("initrd: {e}"));
            return;
        }
    };
    let workspace = match canonicalize_safe(Path::new(workspace_path)) {
        Ok(p) => p,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "bad_path", &format!("workspace: {e}"));
            return;
        }
    };
    let vhdx = match rootfs_vhdx {
        Some(p) => match canonicalize_safe(Path::new(p)) {
            Ok(c) => Some(c),
            Err(e) => {
                let _ = send_error_raw(pipe, &id, "bad_path", &format!("rootfs_vhdx: {e}"));
                return;
            }
        },
        None => None,
    };

    if network == SvcNetwork::AllowAll {
        let _ = send_error_raw(
            pipe,
            &id,
            "not_implemented",
            "NetworkPolicy::AllowAll is not yet implemented on Windows. \
             Use NetworkPolicy::Blocked. (Tracking: AllowAll requires HCN endpoint setup.)",
        );
        return;
    }

    match run_vm(&kernel, &initrd, vhdx.as_deref(), &workspace, cmd_b64, memory_mb, cpu_count) {
        Ok(result) => {
            let _ = send_response_raw(pipe, &SvcResponse::ExecVmResult { id, result });
        }
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "hcs_error", &format!("VM failed: {e}"));
        }
    }
}

fn run_vm(
    kernel: &Path,
    initrd: &Path,
    vhdx: Option<&Path>,
    workspace: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> Result<ExecVmResult, String> {
    // Clean stale guest output files.
    let _ = std::fs::remove_file(workspace.join(".vz_stdout"));
    let _ = std::fs::remove_file(workspace.join(".vz_stderr"));
    let _ = std::fs::remove_file(workspace.join(".vz_exit_code"));

    let vm_id = format!("tokimo-svc-{}", std::process::id());
    let cfg_json = vmconfig::build(&vm_id, kernel, initrd, vhdx, workspace, cmd_b64, memory_mb, cpu_count);

    let api = hcs::HcsApi::init()?;
    let handle = api.create_compute_system(&vm_id, &cfg_json)?;
    let _guard = scopeguard_close(api.clone(), handle);

    api.start_compute_system(handle)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        match api.poll_state(handle) {
            hcs::HcsState::Stopped => break,
            hcs::HcsState::Error => {
                let _ = api.terminate_compute_system(handle);
                return Err("VM entered error state".into());
            }
            hcs::HcsState::Running => {}
        }
        if std::time::Instant::now() > deadline {
            let _ = api.terminate_compute_system(handle);
            return Ok(ExecVmResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                timed_out: true,
            });
        }
    }

    let stdout = std::fs::read_to_string(workspace.join(".vz_stdout")).unwrap_or_default();
    let stderr = std::fs::read_to_string(workspace.join(".vz_stderr")).unwrap_or_default();
    let exit_code = std::fs::read_to_string(workspace.join(".vz_exit_code"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);

    let _ = std::fs::remove_file(workspace.join(".vz_stdout"));
    let _ = std::fs::remove_file(workspace.join(".vz_stderr"));
    let _ = std::fs::remove_file(workspace.join(".vz_exit_code"));

    Ok(ExecVmResult {
        stdout,
        stderr,
        exit_code,
        timed_out: false,
    })
}

/// Tiny RAII guard that always closes the compute system handle.
fn scopeguard_close(api: Arc<hcs::HcsApi>, handle: hcs::CsHandle) -> impl Drop {
    struct G(Arc<hcs::HcsApi>, hcs::CsHandle);
    impl Drop for G {
        fn drop(&mut self) {
            self.0.close_compute_system(self.1);
        }
    }
    G(api, handle)
}

// ---------------------------------------------------------------------------
// Pipe framing
// ---------------------------------------------------------------------------

fn read_request(pipe: HANDLE) -> std::io::Result<SvcRequest> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut payload = vec![0u8; len];
    read_exact(pipe, &mut payload)?;
    serde_json::from_slice(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}")))
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let mut got: u32 = 0;
        let chunk = &mut buf[off..];
        let len = chunk.len() as u32;
        unsafe {
            ReadFile(pipe, Some(chunk), Some(&mut got), None)
                .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }
        if got == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "pipe closed"));
        }
        let _ = len;
        off += got as usize;
    }
    Ok(())
}

fn write_all(pipe: HANDLE, buf: &[u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let mut written: u32 = 0;
        let chunk = &buf[off..];
        unsafe {
            WriteFile(pipe, Some(chunk), Some(&mut written), None)
                .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }
        if written == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "pipe closed"));
        }
        off += written as usize;
    }
    Ok(())
}

fn send_response_raw(pipe: HANDLE, resp: &SvcResponse) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("ser: {e}")))?;
    let len = (bytes.len() as u32).to_le_bytes();
    write_all(pipe, &len)?;
    write_all(pipe, &bytes)
}

fn send_error_raw(pipe: HANDLE, id: &str, code: &str, msg: &str) -> std::io::Result<()> {
    send_response_raw(
        pipe,
        &SvcResponse::Error {
            id: id.to_string(),
            error: SvcError {
                code: code.to_string(),
                message: msg.to_string(),
            },
        },
    )
}

// ---------------------------------------------------------------------------
// Caller verification
// ---------------------------------------------------------------------------

fn verify_caller_required() -> bool {
    if std::env::var("TOKIMO_VERIFY_CALLER").map(|v| v == "1").unwrap_or(false) {
        return true;
    }
    // Check HKLM\SOFTWARE\Tokimo\SandboxSvc\VerifyCaller
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE,
    };
    let subkey = HSTRING::from(r"SOFTWARE\Tokimo\SandboxSvc");
    let value = HSTRING::from("VerifyCaller");
    let mut hk = HKEY::default();
    let r = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &subkey, None, KEY_READ, &mut hk) };
    if r.is_err() {
        return false;
    }
    let mut data: u32 = 0;
    let mut ty = REG_VALUE_TYPE(0);
    let mut sz: u32 = std::mem::size_of::<u32>() as u32;
    let r = unsafe {
        RegQueryValueExW(
            hk,
            &value,
            None,
            Some(&mut ty),
            Some((&mut data as *mut u32) as *mut u8),
            Some(&mut sz),
        )
    };
    let _ = unsafe { RegCloseKey(hk) };
    r.is_ok() && data != 0
}

fn caller_image_path(pipe: HANDLE) -> Option<PathBuf> {
    let mut pid: u32 = 0;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid).ok()? };

    let proc_h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = [0u16; 32 * 1024];
    let mut sz: u32 = buf.len() as u32;
    let r = unsafe { QueryFullProcessImageNameW(proc_h, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut sz) };
    let _ = unsafe { CloseHandle(proc_h) };
    if r.is_err() || sz == 0 {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..sz as usize]);
    Some(PathBuf::from(s))
}

fn verify_authenticode(path: &Path) -> Result<(), String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide_extra().chain(std::iter::once(0)).collect();

    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut wd = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(0),
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &file_info as *const _ as *mut _,
        },
        dwStateAction: WINTRUST_DATA_STATE_ACTION(1), // WTD_STATEACTION_VERIFY
        hWVTStateData: HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WINTRUST_DATA_UICONTEXT(1), // WTD_UICONTEXT_EXECUTE
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = unsafe { WinVerifyTrust(HWND::default(), &mut action, &mut wd as *mut _ as *mut _) };
    if hr == 0 {
        Ok(())
    } else {
        Err(format!("WinVerifyTrust HRESULT 0x{:08X}", hr as u32))
    }
}

// Helper: encode_wide for OsStr (std doesn't expose this on stable as an
// inherent method; the windows crate has HSTRING but we need a Vec<u16>).
trait EncodeWideExtra {
    fn encode_wide_extra(&self) -> std::os::windows::ffi::EncodeWide<'_>;
}
impl EncodeWideExtra for std::ffi::OsStr {
    fn encode_wide_extra(&self) -> std::os::windows::ffi::EncodeWide<'_> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide()
    }
}
