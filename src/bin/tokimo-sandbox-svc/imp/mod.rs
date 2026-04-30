//! Windows-only implementation of the SYSTEM service.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL, HWND, INVALID_HANDLE_VALUE, LocalFree};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
    WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    WaitForSingleObject,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use tokimo_package_sandbox::canonicalize_safe;
use tokimo_package_sandbox::svc_protocol::{
    ExecVmResult, RootfsSpec, ShareSpec, SvcError, SvcNetwork, SvcRequest, SvcResponse, WIRE_PROTOCOL_VERSION,
};

mod hcs;
mod hvsock;
mod vhdx_pool;
mod vmconfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Service name used by MSIX-packaged deployment (declared in
/// `packaging/windows/AppxManifest.xml`'s `desktop6:Service Name=`).
/// The MSIX subsystem registers this name with SCM, so we keep it as the
/// well-known dispatcher name for compatibility.
const SERVICE_NAME: &str = "TokimoSandboxSvc";
/// Service name used by the CLI `--install` / `--uninstall` flow.
/// Deliberately *different* from `SERVICE_NAME` (PascalCase) so a developer
/// install can coexist with an MSIX-packaged install on the same machine
/// — the two names point at distinct SCM entries.
const INSTALL_SERVICE_NAME: &str = "tokimo-sandbox-svc";
const SERVICE_DISPLAY: &str = "Tokimo Sandbox Service";
const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";

/// SDDL for the named pipe when running as a service (LocalSystem).
///
/// `O:SY` owner = LocalSystem
/// `G:SY` group = LocalSystem
/// `D:` DACL:
///   * `(A;;GA;;;SY)` - LocalSystem: GENERIC_ALL
///   * `(A;;0x12019b;;;IU)` - Interactive Users: read|write|sync without
///     delete/changeperms (FILE_GENERIC_READ | FILE_GENERIC_WRITE).
const PIPE_SDDL_SERVICE: &str = "O:SYG:SYD:(A;;GA;;;SY)(A;;0x12019b;;;IU)";

/// SDDL for the named pipe when running in console (dev) mode.
///
/// Does not require LocalSystem as owner so it works under a privileged
/// admin account without `SeRestorePrivilege`. The DACL grants access to
/// the current interactive user session only.
const PIPE_SDDL_CONSOLE: &str = "D:(A;;GA;;;IU)";

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
            // MSIX packaged service passes --service; fall through to the
            // service_dispatcher below.
            "--service" => {}
            "-h" | "--help" => {
                println!("tokimo-sandbox-svc v{VERSION}");
                println!("Usage: tokimo-sandbox-svc [--install|--uninstall|--console|--service]");
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
    println!(
        "Caller verification: {}",
        if verify_caller_required() {
            "ENFORCED"
        } else {
            "log-only"
        }
    );
    println!("Waiting for connections... (Ctrl+C to stop)");
    pipe_server_loop(true);
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

    pipe_server_loop(false);

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
        name: OsString::from(INSTALL_SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("--service")],
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
                eprintln!(
                    "StartService failed (the service is still installed): {}",
                    format_ws_error(&e)
                );
            } else {
                println!("Service installed and started: {INSTALL_SERVICE_NAME}");
            }
        }
        Err(e) => {
            // ERROR_SERVICE_EXISTS (1073) and ERROR_DUPLICATE_SERVICE_NAME
            // (1078) both mean "name is already taken"; treat as no-op.
            match ws_error_code(&e) {
                Some(1073) => println!("Service already installed: {INSTALL_SERVICE_NAME}"),
                Some(1078) => {
                    eprintln!(
                        "Cannot create service '{INSTALL_SERVICE_NAME}': another service is using the same display name '{SERVICE_DISPLAY}' (ERROR_DUPLICATE_SERVICE_NAME 1078). \
This usually means an MSIX package (service '{SERVICE_NAME}') is already installed. Uninstall it via `Get-AppxPackage Tokimo.SandboxSvc | Remove-AppxPackage` and retry."
                    );
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("CreateService failed: {}", format_ws_error(&e));
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Extract the underlying OS error code from a `windows_service::Error`.
/// The crate's `Display` impl is famously useless ("IO error in winapi call")
/// and hides the actual code, so we reach through `Error::source()` for it.
fn ws_error_code(e: &windows_service::Error) -> Option<i32> {
    use std::error::Error;
    e.source()
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .and_then(|io| io.raw_os_error())
}

/// Format a `windows_service::Error` with its OS code attached.
fn format_ws_error(e: &windows_service::Error) -> String {
    match ws_error_code(e) {
        Some(code) => format!("{e} (os error {code})"),
        None => e.to_string(),
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
        INSTALL_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(e) => {
            if matches!(ws_error_code(&e), Some(1060)) {
                println!("Service not installed: {INSTALL_SERVICE_NAME}");
                return;
            }
            eprintln!("OpenService failed: {}", format_ws_error(&e));
            std::process::exit(1);
        }
    };

    if let Ok(status) = svc.query_status()
        && status.current_state != ServiceState::Stopped
    {
        let _ = svc.stop();
        // Wait briefly.
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(200));
            if matches!(svc.query_status().map(|s| s.current_state), Ok(ServiceState::Stopped)) {
                break;
            }
        }
    }

    if let Err(e) = svc.delete() {
        eprintln!("DeleteService failed: {}", format_ws_error(&e));
        std::process::exit(1);
    }
    println!("Service uninstalled: {INSTALL_SERVICE_NAME}");
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

fn build_security_attributes(console_mode: bool) -> std::io::Result<(SECURITY_ATTRIBUTES, SdGuard)> {
    let sddl_str = if console_mode {
        PIPE_SDDL_CONSOLE
    } else {
        PIPE_SDDL_SERVICE
    };
    let sddl = HSTRING::from(sddl_str);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &mut sd, None) }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    Ok((attrs, SdGuard(sd)))
}

fn pipe_server_loop(console_mode: bool) {
    let (mut sa, _sd_guard) = match build_security_attributes(console_mode) {
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
                PIPE_ACCESS_DUPLEX
                    | windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OVERLAPPED.0),
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
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

        // Overlapped ConnectNamedPipe: returns immediately with ERROR_IO_PENDING,
        // wait on the OVERLAPPED event for actual connection.
        let connect_evt = match create_event() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[svc] CreateEventW failed: {e}");
                let _ = unsafe { CloseHandle(pipe) };
                continue;
            }
        };
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = connect_evt;
        let connected = unsafe { ConnectNamedPipe(pipe, Some(&mut ov)) };
        let last = unsafe { GetLastError() }.0;
        if connected.is_err() && last != 535 /* ERROR_PIPE_CONNECTED */ && last != 997
        /* ERROR_IO_PENDING */
        {
            let _ = unsafe { CloseHandle(connect_evt) };
            let _ = unsafe { CloseHandle(pipe) };
            continue;
        }
        if last == 997 {
            // Wait for the connection to actually complete.
            unsafe { WaitForSingleObject(connect_evt, u32::MAX) };
        }
        let _ = unsafe { CloseHandle(connect_evt) };

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
            rootfs_dir,
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
                &rootfs_dir,
                &workspace_path,
                &cmd_b64,
                memory_mb,
                cpu_count,
                network,
            );
        }
        SvcRequest::OpenSession {
            id,
            protocol_version,
            kernel_path,
            initrd_path,
            rootfs,
            shares,
            memory_mb,
            cpu_count,
            network,
        } => {
            handle_open_session(
                pipe,
                id,
                protocol_version,
                &kernel_path,
                &initrd_path,
                rootfs,
                shares,
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
    rootfs_dir_str: &str,
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
    let rootfs_dir = match canonicalize_safe(Path::new(rootfs_dir_str)) {
        Ok(p) => p,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "bad_path", &format!("rootfs_dir: {e}"));
            return;
        }
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

    match run_vm(&kernel, &initrd, &rootfs_dir, &workspace, cmd_b64, memory_mb, cpu_count) {
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
    rootfs_dir: &Path,
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
    let cfg_json = vmconfig::build(
        &vm_id, kernel, initrd, rootfs_dir, workspace, cmd_b64, memory_mb, cpu_count,
    );

    // Debug: dump the HCS config JSON to a known location so failures can
    // be inspected post-mortem from the test harness.
    let _ = std::fs::write(r"C:\tokimo-debug\last-hcs-config.json", &cfg_json);

    // Spawn a thread that hosts the COM1 named pipe server and tails serial
    // output into C:\tokimo-debug\last-vm-com1.log. HCS connects to this pipe
    // when the VM starts; we keep accepting reads until the VM stops.
    spawn_com1_logger(&vm_id);

    let api = hcs::HcsApi::init()?;
    let handle = match api.create_compute_system(&vm_id, &cfg_json) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::write(r"C:\tokimo-debug\last-hcs-error.txt", &e);
            return Err(e);
        }
    };
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

/// Hosts the named pipe server for COM1 and tails everything HCS writes to
/// it into `C:\tokimo-debug\last-vm-com1.log`. Truncates the log first.
fn spawn_com1_logger(vm_id: &str) {
    spawn_com_logger(
        &format!(r"\\.\pipe\tokimo-vm-com1-{vm_id}"),
        r"C:\tokimo-debug\last-vm-com1.log",
    );
}

/// Generic version: any COM port to any log path.
fn spawn_com_logger(pipe_name: &str, log_path: &'static str) {
    let _ = std::fs::write(log_path, b"");
    let pipe_w = HSTRING::from(pipe_name);
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while std::time::Instant::now() < deadline {
            let pipe = unsafe {
                CreateNamedPipeW(
                    &pipe_w,
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    4096,
                    4096,
                    50,
                    None,
                )
            };
            if pipe == INVALID_HANDLE_VALUE {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            let connected = unsafe { ConnectNamedPipe(pipe, None) };
            if connected.is_err() {
                let last = unsafe { GetLastError() }.0;
                if last != 535 {
                    let _ = unsafe { CloseHandle(pipe) };
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
            let mut buf = [0u8; 1024];
            loop {
                let mut got: u32 = 0;
                let r = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut got), None) };
                if r.is_err() || got == 0 {
                    break;
                }
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
                    let _ = f.write_all(&buf[..got as usize]);
                }
            }
            let _ = unsafe { CloseHandle(pipe) };
            return;
        }
    });
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

fn create_event() -> std::io::Result<HANDLE> {
    let h = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
    Ok(h)
}

/// Synchronous-style ReadFile on an OVERLAPPED handle. Issues an
/// overlapped read and waits for completion via WaitForSingleObject.
unsafe fn ov_read(pipe: HANDLE, buf: &mut [u8]) -> std::io::Result<u32> {
    let evt = create_event()?;
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = evt;
    let mut got: u32 = 0;
    let r = unsafe { ReadFile(pipe, Some(buf), Some(&mut got), Some(&mut ov)) };
    let last = unsafe { GetLastError() }.0;
    tunnel_log(&format!(
        "ov_read ReadFile r.is_err={} last={last} got={got}",
        r.is_err()
    ));
    if r.is_err() {
        if last == 997
        /* ERROR_IO_PENDING */
        {
            tunnel_log("ov_read waiting on event");
            unsafe { WaitForSingleObject(evt, u32::MAX) };
            tunnel_log("ov_read event signaled");
            let mut transferred: u32 = 0;
            let ok = unsafe { windows::Win32::System::IO::GetOverlappedResult(pipe, &ov, &mut transferred, false) };
            unsafe {
                let _ = CloseHandle(evt);
            }
            if ok.is_err() {
                let last2 = unsafe { GetLastError() }.0;
                return Err(std::io::Error::from_raw_os_error(last2 as i32));
            }
            return Ok(transferred);
        }
        unsafe {
            let _ = CloseHandle(evt);
        }
        return Err(std::io::Error::from_raw_os_error(last as i32));
    }
    unsafe {
        let _ = CloseHandle(evt);
    }
    Ok(got)
}

unsafe fn ov_write(pipe: HANDLE, buf: &[u8]) -> std::io::Result<u32> {
    let evt = create_event()?;
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = evt;
    let mut wrote: u32 = 0;
    let r = unsafe { WriteFile(pipe, Some(buf), Some(&mut wrote), Some(&mut ov)) };
    if r.is_err() {
        let last = unsafe { GetLastError() }.0;
        if last == 997 {
            unsafe { WaitForSingleObject(evt, u32::MAX) };
            let mut transferred: u32 = 0;
            let ok = unsafe { windows::Win32::System::IO::GetOverlappedResult(pipe, &ov, &mut transferred, false) };
            unsafe {
                let _ = CloseHandle(evt);
            }
            if ok.is_err() {
                let last2 = unsafe { GetLastError() }.0;
                return Err(std::io::Error::from_raw_os_error(last2 as i32));
            }
            return Ok(transferred);
        }
        unsafe {
            let _ = CloseHandle(evt);
        }
        return Err(std::io::Error::from_raw_os_error(last as i32));
    }
    unsafe {
        let _ = CloseHandle(evt);
    }
    Ok(wrote)
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let got = unsafe { ov_read(pipe, &mut buf[off..])? };
        if got == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "pipe closed"));
        }
        off += got as usize;
    }
    Ok(())
}

fn write_all(pipe: HANDLE, buf: &[u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let written = unsafe { ov_write(pipe, &buf[off..])? };
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
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
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

/// Register an HvSocket service GUID under
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\<guid>`.
/// Idempotent — if the key already exists we just refresh the friendly name.
fn ensure_hvsocket_service_registered(svc_guid: &str, friendly_name: &str) -> Result<(), String> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATE_KEY_DISPOSITION, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegSetValueExW,
    };

    let subkey = HSTRING::from(format!(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\{svc_guid}"
    ));
    let mut hk = HKEY::default();
    let mut disp = REG_CREATE_KEY_DISPOSITION(0);
    let r = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            &subkey,
            None,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hk,
            Some(&mut disp),
        )
    };
    if r != ERROR_SUCCESS {
        return Err(format!("RegCreateKeyExW {svc_guid}: {:?}", r));
    }
    let value_name = HSTRING::from("ElementName");
    let wide: Vec<u16> = friendly_name.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    let r2 = unsafe { RegSetValueExW(hk, &value_name, None, REG_SZ, Some(bytes)) };

    // Set SecurityDescriptor REG_SZ so the guest's hv_sock connect to this
    // service GUID is granted access. Without this the guest's connect can
    // be silently dropped (ETIMEDOUT) — Hyper-V doesn't surface a refusal.
    let sd_name = HSTRING::from("SecurityDescriptor");
    let sd_str = "D:(A;;GA;;;WD)";
    let sd_wide: Vec<u16> = sd_str.encode_utf16().chain(std::iter::once(0)).collect();
    let sd_bytes: &[u8] = unsafe { std::slice::from_raw_parts(sd_wide.as_ptr() as *const u8, sd_wide.len() * 2) };
    let _ = unsafe { RegSetValueExW(hk, &sd_name, None, REG_SZ, Some(sd_bytes)) };

    let _ = unsafe { RegCloseKey(hk) };
    if r2 != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW: {:?}", r2));
    }
    Ok(())
}

fn caller_image_path(pipe: HANDLE) -> Option<PathBuf> {
    let mut pid: u32 = 0;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid).ok()? };

    let proc_h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = [0u16; 32 * 1024];
    let mut sz: u32 = buf.len() as u32;
    let r = unsafe {
        QueryFullProcessImageNameW(
            proc_h,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut sz,
        )
    };
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

// ---------------------------------------------------------------------------
// OpenSession — long-lived VM, COM1 tunneled to client pipe
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn handle_open_session(
    pipe: HANDLE,
    id: String,
    protocol_version: u32,
    kernel_path: &str,
    initrd_path: &str,
    rootfs: RootfsSpec,
    shares: Vec<ShareSpec>,
    memory_mb: u64,
    cpu_count: usize,
    network: SvcNetwork,
) {
    if protocol_version != WIRE_PROTOCOL_VERSION {
        let _ = send_error_raw(
            pipe,
            &id,
            "bad_protocol",
            &format!("client wire protocol_version={protocol_version}, service expects {WIRE_PROTOCOL_VERSION}"),
        );
        return;
    }
    if network == SvcNetwork::AllowAll {
        let _ = send_error_raw(
            pipe,
            &id,
            "not_implemented",
            "NetworkPolicy::AllowAll is not yet implemented on Windows. Use Blocked.",
        );
        return;
    }
    if shares.is_empty() {
        let _ = send_error_raw(pipe, &id, "bad_request", "shares list is empty");
        return;
    }
    if shares.len() > 64 {
        let _ = send_error_raw(
            pipe,
            &id,
            "bad_request",
            &format!("too many shares: {} (max 64)", shares.len()),
        );
        return;
    }

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

    // Canonicalize every share's host path (TOCTOU-safe; rejects symlinks
    // and reparse points). Build the canonical list up front so we never
    // pass an attacker-influenced path into HCS.
    let mut canonical_shares: Vec<(PathBuf, ShareSpec)> = Vec::with_capacity(shares.len());
    for (i, s) in shares.iter().enumerate() {
        match canonicalize_safe(Path::new(&s.host_path)) {
            Ok(p) => canonical_shares.push((p, s.clone())),
            Err(e) => {
                let _ = send_error_raw(
                    pipe,
                    &id,
                    "bad_path",
                    &format!("shares[{i}].host_path ({}): {e}", s.host_path),
                );
                return;
            }
        }
    }

    let vm_id = format!("tokimo-sess-{}-{}", std::process::id(), rand_session_suffix());

    // Acquire a rootfs lease (ephemeral clones the template; persistent
    // locks the caller-supplied target path so concurrent sessions for
    // the same target are rejected with `persistent_busy`).
    let scratch_dir: PathBuf = {
        // For ephemeral, drop the clone next to the first share for
        // workspace-locality. For persistent, the lease's path is the
        // caller's own path so the scratch_dir doesn't matter.
        canonical_shares[0].0.clone()
    };
    let vhdx_lease = match vhdx_pool::acquire(&rootfs, &scratch_dir, &vm_id) {
        Ok(l) => l,
        Err(vhdx_pool::PoolError::Busy(p)) => {
            let _ = send_error_raw(
                pipe,
                &id,
                "persistent_busy",
                &format!("rootfs target already in use: {}", p.display()),
            );
            return;
        }
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "vhdx_pool", &e.to_string());
            return;
        }
    };

    // Allocate the init control port + one port per share. We bind a
    // WILDCARD listener for the init control plane only — Plan9 share
    // ports are owned by HCS (its internal Plan9 device serves 9p on
    // each `Plan9.Shares[i].Port`), so we MUST NOT register their
    // service GUIDs or bind listeners that would race HCS.
    let init_port = vmconfig::alloc_session_init_port();
    let init_svc_id = vmconfig::hvsock_service_id(init_port);
    if let Err(e) = ensure_hvsocket_service_registered(&init_svc_id, "Tokimo Sandbox Init") {
        let _ = send_error_raw(pipe, &id, "hvsock_register", &e);
        return;
    }
    let init_svc_guid = match parse_guid(&init_svc_id) {
        Ok(g) => g,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "guid", &e);
            return;
        }
    };
    let init_listener = match hvsock::listen_for_guest(hvsock::HV_GUID_WILDCARD, init_svc_guid) {
        Ok(l) => l,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "hvsock_listen", &e.to_string());
            return;
        }
    };

    // Allocate per-share vsock ports up front so the V2 schema can list
    // them all in `Plan9.Shares` and the response can echo `share_ports`
    // back to the library (which forwards them to the guest in the
    // `MountManifest` op). HCS provides the host-side endpoint for each.
    let share_ports: Vec<u32> = (0..canonical_shares.len())
        .map(|_| vmconfig::alloc_share_port())
        .collect();

    let v2_shares: Vec<vmconfig::V2Share<'_>> = canonical_shares
        .iter()
        .zip(share_ports.iter())
        .map(|((host_path, spec), port)| vmconfig::V2Share {
            host_path: host_path.as_path(),
            name: spec.name.as_str(),
            port: *port,
            read_only: spec.read_only,
        })
        .collect();

    let cfg_json = vmconfig::build_session_v2(
        &vm_id,
        &kernel,
        &initrd,
        vhdx_lease.path(),
        &v2_shares,
        memory_mb,
        cpu_count,
        init_port,
    );
    let _ = std::fs::write(r"C:\tokimo-debug\last-hcs-session-config.json", &cfg_json);

    spawn_com_logger(
        &format!(r"\\.\pipe\tokimo-vm-com2-{vm_id}"),
        r"C:\tokimo-debug\last-vm-com2.log",
    );

    eprintln!(
        "[svc] session {vm_id} listening on AF_HYPERV: init={init_svc_id}, {} share(s)",
        canonical_shares.len()
    );

    let api = match hcs::HcsApi::init() {
        Ok(a) => a,
        Err(e) => {
            let _ = send_error_raw(pipe, &id, "hcs_init", &e);
            return;
        }
    };
    let cs = match api.create_compute_system(&vm_id, &cfg_json) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::write(r"C:\tokimo-debug\last-hcs-error.txt", &e);
            let _ = send_error_raw(pipe, &id, "hcs_create", &e);
            return;
        }
    };
    if let Err(e) = api.start_compute_system(cs) {
        api.close_compute_system(cs);
        let _ = send_error_raw(pipe, &id, "hcs_start", &e);
        return;
    }

    // Send SessionOpened *before* we start blocking on `accept_guest` —
    // the host's WinInitClient pumps reads in a background thread so we
    // can interleave the OpenSession reply and tunnel bytes safely.
    if let Err(e) = send_response_raw(
        pipe,
        &SvcResponse::SessionOpened {
            id: id.clone(),
            protocol_version: WIRE_PROTOCOL_VERSION,
            init_port,
            share_ports: share_ports.clone(),
        },
    ) {
        api.terminate_compute_system(cs).ok();
        api.close_compute_system(cs);
        eprintln!("[svc] failed to send SessionOpened: {e}");
        return;
    }

    // Wait for the guest to dial the init control port. The share ports
    // are accepted lazily — one accept thread per share, each one
    // blocks on its own listener until the guest's MountManifest
    // handler dials in.
    let mut hv = match hvsock::accept_guest(&init_listener, Duration::from_secs(60)) {
        Ok(s) => s,
        Err(e) => {
            api.terminate_compute_system(cs).ok();
            api.close_compute_system(cs);
            eprintln!("[svc] hvsock(init) accept failed: {e}");
            return;
        }
    };
    drop(init_listener);
    eprintln!("[svc] session {vm_id} init hvsock connected");

    // Plan9 share connections are handled entirely by HCS — the guest
    // dials each share's vsock port (relayed via `MountManifest`) and
    // HCS's internal Plan9 server takes care of byte-level 9p traffic
    // backed by the host directory specified in `Plan9.Shares[i].Path`.

    let mut hv2 = match hv.try_clone() {
        Ok(h) => h,
        Err(e) => {
            api.terminate_compute_system(cs).ok();
            api.close_compute_system(cs);
            eprintln!("[svc] hvsock clone failed: {e}");
            return;
        }
    };
    let client_ptr = pipe.0 as usize;
    let cli_read_h: usize = unsafe {
        use windows::Win32::Foundation::DUPLICATE_SAME_ACCESS;
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut dup = HANDLE(std::ptr::null_mut());
        let proc = GetCurrentProcess();
        let _ = windows::Win32::Foundation::DuplicateHandle(
            proc,
            HANDLE(client_ptr as *mut _),
            proc,
            &mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        );
        dup.0 as usize
    };
    let dead = Arc::new(AtomicBool::new(false));

    let dead_a = dead.clone();
    let _t = std::thread::spawn(move || {
        tunnel_log("client→hv thread started");
        let cli = HANDLE(cli_read_h as *mut _);
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        loop {
            if dead_a.load(Ordering::Relaxed) {
                break;
            }
            let got = match unsafe { ov_read(cli, &mut buf) } {
                Ok(g) => g,
                Err(e) => {
                    tunnel_log(&format!("client→hv read failed: {e}"));
                    break;
                }
            };
            if got == 0 {
                tunnel_log(&format!("client→hv EOF total={total}"));
                break;
            }
            total += got as u64;
            tunnel_log(&format!("client→hv +{got}B (total {total})"));
            use std::io::Write;
            if let Err(e) = hv2.write_all(&buf[..got as usize]) {
                tunnel_log(&format!("client→hv write failed: {e}"));
                break;
            }
        }
        dead_a.store(true, Ordering::Relaxed);
    });

    {
        tunnel_log("hv→client loop start");
        let cli = HANDLE(client_ptr as *mut _);
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        use std::io::Read;
        loop {
            if dead.load(Ordering::Relaxed) {
                break;
            }
            let n = match hv.read(&mut buf) {
                Ok(0) => {
                    tunnel_log(&format!("hv→client EOF total={total}"));
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    tunnel_log(&format!("hv→client read failed: {e}"));
                    break;
                }
            };
            total += n as u64;
            tunnel_log(&format!("hv→client +{n}B (total {total})"));
            let mut off = 0usize;
            while off < n {
                tunnel_log(&format!("hv→client about to ov_write {}B", n - off));
                let wrote = match unsafe { ov_write(cli, &buf[off..n]) } {
                    Ok(w) => w,
                    Err(e) => {
                        tunnel_log(&format!("hv→client ov_write failed: {e}"));
                        break;
                    }
                };
                if wrote == 0 {
                    tunnel_log("hv→client ov_write zero");
                    break;
                }
                tunnel_log(&format!("hv→client wrote {wrote}B"));
                off += wrote as usize;
            }
            let _ = unsafe { FlushFileBuffers(cli) };
        }
        dead.store(true, Ordering::Relaxed);
    }

    eprintln!("[svc] session {vm_id} tunnel closed, tearing down VM");
    api.terminate_compute_system(cs).ok();
    api.close_compute_system(cs);
    // vhdx_lease drop releases the per-target mutex and (for ephemeral
    // leases) deletes the per-session VHDX clone.
    drop(vhdx_lease);
}

fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (n & 0xFFFF) as u16 ^ ((n >> 16) as u16)
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    n.wrapping_mul(0x9E3779B97F4A7C15)
}

/// Parse a string GUID `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` into a
/// `windows::core::GUID`.
fn parse_guid(s: &str) -> Result<windows::core::GUID, String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return Err(format!("bad GUID format: {s}"));
    }
    let data1 = u32::from_str_radix(parts[0], 16).map_err(|e| e.to_string())?;
    let data2 = u16::from_str_radix(parts[1], 16).map_err(|e| e.to_string())?;
    let data3 = u16::from_str_radix(parts[2], 16).map_err(|e| e.to_string())?;
    if parts[3].len() != 4 || parts[4].len() != 12 {
        return Err(format!("bad GUID part lengths: {s}"));
    }
    let mut data4 = [0u8; 8];
    for i in 0..2 {
        data4[i] = u8::from_str_radix(&parts[3][i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    for i in 0..6 {
        data4[2 + i] = u8::from_str_radix(&parts[4][i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(windows::core::GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn rand_session_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:08x}", nanos)
}

fn tunnel_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\tokimo-debug\last-vm-tunnel.log")
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(f, "[{now}] {msg}");
    }
}
