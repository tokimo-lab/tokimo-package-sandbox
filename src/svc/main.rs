//! tokimo-sandbox-svc — Windows SYSTEM service for HCS VM management.
//!
//! Usage:
//!   tokimo-sandbox-svc --install     Install & start the service (needs admin)
//!   tokimo-sandbox-svc --uninstall   Stop & remove the service (needs admin)
//!   tokimo-sandbox-svc               Run as a Windows service (called by SCM)

#![cfg(target_os = "windows")]

use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Direct FFI to avoid windows-sys module path churn
// ---------------------------------------------------------------------------

// kernel32 functions (linked by default)
extern "system" {
    fn LoadLibraryW(lpFileName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn FreeLibrary(hModule: *mut c_void) -> i32;
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    fn GetLastError() -> u32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
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
    fn FlushFileBuffers(hFile: *mut c_void) -> i32;
    fn CreateNamedPipeW(
        lpName: *const u16,
        dwOpenMode: u32,
        dwPipeMode: u32,
        nMaxInstances: u32,
        nOutBufferSize: u32,
        nInBufferSize: u32,
        nDefaultTimeOut: u32,
        lpSecurityAttributes: *mut c_void,
    ) -> *mut c_void;
    fn ConnectNamedPipe(hNamedPipe: *mut c_void, lpOverlapped: *mut c_void) -> i32;
    fn DisconnectNamedPipe(hNamedPipe: *mut c_void) -> i32;
}

// advapi32 functions
#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(lpMachineName: *const u16, lpDatabaseName: *const u16, dwDesiredAccess: u32) -> *mut c_void;
    fn CreateServiceW(
        hSCManager: *mut c_void,
        lpServiceName: *const u16,
        lpDisplayName: *const u16,
        dwDesiredAccess: u32,
        dwServiceType: u32,
        dwStartType: u32,
        dwErrorControl: u32,
        lpBinaryPathName: *const u16,
        lpLoadOrderGroup: *const u16,
        lpdwTagId: *mut u32,
        lpDependencies: *const u16,
        lpServiceStartName: *const u16,
        lpPassword: *const u16,
    ) -> *mut c_void;
    fn OpenServiceW(hSCManager: *mut c_void, lpServiceName: *const u16, dwDesiredAccess: u32) -> *mut c_void;
    fn StartServiceW(hService: *mut c_void, dwNumServiceArgs: u32, lpServiceArgVectors: *const *const u16) -> i32;
    fn ControlService(hService: *mut c_void, dwControl: u32, lpServiceStatus: *mut SERVICE_STATUS) -> i32;
    fn DeleteService(hService: *mut c_void) -> i32;
    fn CloseServiceHandle(hSCObject: *mut c_void) -> i32;
    fn StartServiceCtrlDispatcherW(lpServiceStartTable: *const SERVICE_TABLE_ENTRYW) -> i32;
    fn ChangeServiceConfig2W(hService: *mut c_void, dwInfoLevel: u32, lpInfo: *mut c_void) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        StringSecurityDescriptor: *const u16,
        StringSDRevision: u32,
        SecurityDescriptor: *mut *mut c_void,
        SecurityDescriptorSize: *mut u32,
    ) -> i32;
}

// ---------------------------------------------------------------------------
// Win32 constants
// ---------------------------------------------------------------------------

type HCS_OP = *mut c_void;
type HCS_CS = *mut c_void;
type HRES = i32;

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: *mut c_void = usize::MAX as *mut c_void;
const ERROR_PIPE_CONNECTED: u32 = 535;
const ERROR_SERVICE_EXISTS: u32 = 1073;
const ERROR_SERVICE_NOT_FOUND: u32 = 1060;

const PIPE_ACCESS_DUPLEX: u32 = 3;
const PIPE_TYPE_MESSAGE: u32 = 4;
const PIPE_READMODE_MESSAGE: u32 = 2;
const PIPE_WAIT: u32 = 0;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x80000;
const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;

const SC_MANAGER_CREATE_SERVICE: u32 = 2;
const SERVICE_START: u32 = 0x10;
const SERVICE_STOP: u32 = 0x20;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
const SERVICE_AUTO_START: u32 = 2;
const SERVICE_NO_CHANGE: u32 = 0xffffffff;
const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: u32 = 3;
const SERVICE_CONTROL_STOP: u32 = 1;

const SDDL_REVISION_1: u32 = 1;

const SERVICE_NAME: &str = "TokimoSandboxSvc";
const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BU)";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[repr(C)]
#[derive(Copy, Clone)]
struct SERVICE_STATUS {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
}

type LPSERVICE_MAIN_FUNCTIONW =
    Option<unsafe extern "system" fn(dwNumServicesArgs: u32, lpServiceArgVectors: *mut *mut u16)>;

#[repr(C)]
#[derive(Copy, Clone)]
struct SERVICE_TABLE_ENTRYW {
    lpServiceName: *mut u16,
    lpServiceProc: LPSERVICE_MAIN_FUNCTIONW,
}

#[repr(C)]
struct SERVICE_DELAYED_AUTO_START_INFO {
    fDelayedAutostart: i32,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => return install_service(),
            "--uninstall" => return uninstall_service(),
            "--console" => return run_console(),
            "-h" | "--help" => {
                println!("tokimo-sandbox-svc v{VERSION}");
                println!("Usage: tokimo-sandbox-svc [--install|--uninstall|--console]");
                println!("  --install   Install and start as Windows service (needs admin)");
                println!("  --uninstall Stop and remove the Windows service (needs admin)");
                println!("  --console   Run pipe server in foreground (for debugging)");
                println!("  (no args)   Run as Windows service (called by SCM)");
                return;
            }
            other => {
                eprintln!("Unknown option: {other}");
                eprintln!("Usage: tokimo-sandbox-svc [--install|--uninstall|--console]");
                std::process::exit(1);
            }
        }
    }
    run_service();
}

/// Run the pipe server in the foreground for local debugging.
fn run_console() {
    println!("Tokimo Sandbox Service v{VERSION} (console mode)");
    println!("Pipe: {PIPE_NAME}");
    println!("Waiting for connections... (Ctrl+C to stop)");
    pipe_server_loop();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_wide(s: &str) -> Vec<u16> {
    OsString::from(s).encode_wide().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

fn install_service() {
    let exe_path = std::env::current_exe().expect("current_exe");
    let exe_str = to_wide(&exe_path.to_string_lossy());
    let svc_name = to_wide(SERVICE_NAME);

    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
    if scm.is_null() {
        eprintln!("OpenSCManagerW failed: {}", unsafe { GetLastError() });
        std::process::exit(1);
    }

    let svc = unsafe {
        CreateServiceW(
            scm,
            svc_name.as_ptr(),
            svc_name.as_ptr(),
            SERVICE_START | SERVICE_STOP,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_NO_CHANGE,
            exe_str.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };

    if svc.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_EXISTS {
            println!("Service already installed.");
        } else {
            eprintln!("CreateServiceW failed: {err}");
            unsafe { CloseHandle(scm) };
            std::process::exit(1);
        }
    }

    if !svc.is_null() {
        let mut delayed = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: 1 };
        unsafe {
            ChangeServiceConfig2W(
                svc,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                &mut delayed as *mut _ as *mut c_void,
            );
        }
        unsafe { StartServiceW(svc, 0, ptr::null()) };
        unsafe { CloseServiceHandle(svc) };
    }
    unsafe { CloseHandle(scm) };
    println!("Service installed and started: {SERVICE_NAME}");
}

fn uninstall_service() {
    let svc_name = to_wide(SERVICE_NAME);
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
    if scm.is_null() {
        eprintln!("OpenSCManagerW failed: {}", unsafe { GetLastError() });
        std::process::exit(1);
    }

    let svc = unsafe { OpenServiceW(scm, svc_name.as_ptr(), SERVICE_STOP) };
    if svc.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_NOT_FOUND {
            println!("Service not installed.");
            unsafe { CloseHandle(scm) };
            return;
        }
        eprintln!("OpenServiceW failed: {err}");
        unsafe { CloseHandle(scm) };
        std::process::exit(1);
    }

    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) };
    println!("Service stop requested.");
    unsafe { CloseServiceHandle(svc) };

    let svc = unsafe { OpenServiceW(scm, svc_name.as_ptr(), SERVICE_START) };
    if !svc.is_null() {
        if unsafe { DeleteService(svc) } == 0 {
            eprintln!("DeleteService failed: {}", unsafe { GetLastError() });
        } else {
            println!("Service deleted.");
        }
        unsafe { CloseServiceHandle(svc) };
    }
    unsafe { CloseHandle(scm) };
}

// ---------------------------------------------------------------------------
// Service runtime
// ---------------------------------------------------------------------------

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn run_service() {
    let svc_name = to_wide(SERVICE_NAME);
    let svc_name_ptr = svc_name.as_ptr() as *mut u16;

    let mut svc_name_mut = svc_name;
    let svc_name_mut_ptr = svc_name_mut.as_mut_ptr();

    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: svc_name_ptr,
            lpServiceProc: Some(service_main_wrapper),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    unsafe {
        StartServiceCtrlDispatcherW(table.as_ptr());
    }

    let _ = svc_name_mut_ptr; // keep alive
}

unsafe extern "system" fn service_main_wrapper(_: u32, _: *mut *mut u16) {
    pipe_server_loop();
}

fn pipe_server_loop() {
    let pipe_name = to_wide(PIPE_NAME);
    let sddl = to_wide(PIPE_SDDL);

    let mut sd_ptr: *mut c_void = ptr::null_mut();
    let mut sd_size: u32 = 0;
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd_ptr, &mut sd_size)
    };
    if ok == 0 {
        eprintln!("SDDL conversion failed: {}", unsafe { GetLastError() });
        std::process::exit(1);
    }

    println!("Tokimo Sandbox Service starting on {PIPE_NAME} (v{VERSION})");

    let security_attr = sd_ptr;

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }

        let pipe = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                security_attr,
            )
        };

        if pipe == INVALID_HANDLE {
            eprintln!("CreateNamedPipeW failed: {}", unsafe { GetLastError() });
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        let connected = unsafe { ConnectNamedPipe(pipe, ptr::null_mut()) };
        let err = unsafe { GetLastError() };
        if connected == 0 && err != ERROR_PIPE_CONNECTED {
            unsafe { CloseHandle(pipe) };
            continue;
        }

        // Raw pointer is not Send; spawn via a helper.
        spawn_worker(pipe);
    }

    if !sd_ptr.is_null() {
        unsafe { LocalFree(sd_ptr) };
    }
}

fn spawn_worker(pipe: *mut c_void) {
    // spawn takes F: Send + 'static. *mut c_void is not Send, so
    // erect a safe boundary via extern "system" indirection.
    extern "system" fn trampoline(pipe: *mut c_void) -> u32 {
        handle_client(pipe);
        0
    }
    // CreateThread wants a raw entry point; std::thread::spawn does not.
    // Just use std CreateThread via extern.
    let mut tid: u32 = 0;
    unsafe {
        extern "system" {
            fn CreateThread(
                lpThreadAttributes: *mut c_void,
                dwStackSize: usize,
                lpStartAddress: unsafe extern "system" fn(*mut c_void) -> u32,
                lpParameter: *mut c_void,
                dwCreationFlags: u32,
                lpThreadId: *mut u32,
            ) -> *mut c_void;
            fn CloseHandle(h: *mut c_void) -> i32;
        }
        let h = CreateThread(ptr::null_mut(), 0, trampoline, pipe, 0, &mut tid);
        if !h.is_null() {
            CloseHandle(h);
        }
    }
}

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

fn handle_client(pipe: *mut c_void) {
    // Read 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    let mut bytes_read: u32 = 0;
    if unsafe {
        ReadFile(
            pipe,
            len_buf.as_mut_ptr() as *mut c_void,
            4,
            &mut bytes_read,
            ptr::null_mut(),
        )
    } == 0
        || bytes_read != 4
    {
        disconnect(pipe);
        return;
    }

    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if payload_len > 16 * 1024 * 1024 {
        send_error(pipe, "bad_request", "frame too large");
        return;
    }

    let mut payload = vec![0u8; payload_len];
    if unsafe {
        ReadFile(
            pipe,
            payload.as_mut_ptr() as *mut c_void,
            payload_len as u32,
            &mut bytes_read,
            ptr::null_mut(),
        )
    } == 0
        || bytes_read as usize != payload_len
    {
        disconnect(pipe);
        return;
    }

    let request: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(e) => {
            send_error(pipe, "bad_request", &format!("JSON parse: {e}"));
            return;
        }
    };

    let op = request["op"].as_str().unwrap_or("unknown");
    match op {
        "Ping" => {
            let id = request["id"].as_str().unwrap_or("");
            send_json(
                pipe,
                &serde_json::json!({
                    "kind": "Pong", "id": id, "version": VERSION,
                }),
            );
        }
        "ExecVm" => handle_exec_vm(pipe, &request),
        _ => send_error(pipe, "bad_request", &format!("unknown op: {op}")),
    }

    disconnect(pipe);
}

fn disconnect(pipe: *mut c_void) {
    unsafe { FlushFileBuffers(pipe) };
    unsafe { DisconnectNamedPipe(pipe) };
    unsafe { CloseHandle(pipe) };
}

// ---------------------------------------------------------------------------
// ExecVm handler
// ---------------------------------------------------------------------------

fn handle_exec_vm(pipe: *mut c_void, request: &serde_json::Value) {
    let id = request["id"].as_str().unwrap_or("").to_string();
    let kernel_path = request["kernel_path"].as_str().unwrap_or("");
    let initrd_path = request["initrd_path"].as_str().unwrap_or("");
    let rootfs_path = request["rootfs_path"].as_str().unwrap_or("");
    let cmd_b64 = request["cmd_b64"].as_str().unwrap_or("");
    let memory_mb = request["memory_mb"].as_u64().unwrap_or(512);
    let cpu_count = request["cpu_count"].as_u64().unwrap_or(2) as usize;

    if kernel_path.is_empty() || initrd_path.is_empty() || rootfs_path.is_empty() {
        send_error(pipe, "not_found", &format!("missing paths for request {id}"));
        return;
    }

    for (name, path) in [
        ("kernel", kernel_path),
        ("initrd", initrd_path),
        ("rootfs", rootfs_path),
    ] {
        if !Path::new(path).exists() {
            send_error(pipe, "not_found", &format!("{name} not found: {path}"));
            return;
        }
    }

    match run_vm(kernel_path, initrd_path, rootfs_path, cmd_b64, memory_mb, cpu_count) {
        Ok(result) => send_json(
            pipe,
            &serde_json::json!({
                "kind": "ExecVmResult", "id": id,
                "stdout": result.stdout, "stderr": result.stderr,
                "exit_code": result.exit_code, "timed_out": result.timed_out,
            }),
        ),
        Err(e) => send_error(pipe, "hcs_error", &format!("VM execution failed: {e}")),
    }
}

struct VmResult {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
}

fn run_vm(
    kernel_path: &str,
    initrd_path: &str,
    rootfs_path: &str,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> Result<VmResult, String> {
    let rootfs = Path::new(rootfs_path);
    let _ = std::fs::remove_file(rootfs.join(".vz_stdout"));
    let _ = std::fs::remove_file(rootfs.join(".vz_stderr"));
    let _ = std::fs::remove_file(rootfs.join(".vz_exit_code"));

    let vm_id = format!("tokimo-svc-{}", std::process::id());
    let config_json = build_vm_json(
        &vm_id,
        Path::new(kernel_path),
        Path::new(initrd_path),
        rootfs,
        cmd_b64,
        memory_mb,
        cpu_count,
    );

    let hcs = HcsApi::init()?;
    let handle = hcs.create_compute_system(&vm_id, &config_json)?;
    hcs.start_compute_system(handle)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        match hcs.poll_state(handle) {
            HcsState::Stopped => break,
            HcsState::Error => {
                let _ = hcs.terminate_compute_system(handle);
                hcs.close_compute_system(handle);
                return Err("VM entered error state".into());
            }
            HcsState::Running => {}
        }
        if std::time::Instant::now() > deadline {
            let _ = hcs.terminate_compute_system(handle);
            hcs.close_compute_system(handle);
            return Ok(VmResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                timed_out: true,
            });
        }
    }

    let stdout = std::fs::read_to_string(rootfs.join(".vz_stdout")).unwrap_or_default();
    let stderr = std::fs::read_to_string(rootfs.join(".vz_stderr")).unwrap_or_default();
    let exit_code = std::fs::read_to_string(rootfs.join(".vz_exit_code"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);

    let _ = std::fs::remove_file(rootfs.join(".vz_stdout"));
    let _ = std::fs::remove_file(rootfs.join(".vz_stderr"));
    let _ = std::fs::remove_file(rootfs.join(".vz_exit_code"));

    hcs.close_compute_system(handle);
    Ok(VmResult {
        stdout,
        stderr,
        exit_code,
        timed_out: false,
    })
}

// ---------------------------------------------------------------------------
// HCS FFI (self-contained)
// ---------------------------------------------------------------------------

type PfnCreateOp = unsafe extern "system" fn(*mut c_void, *mut c_void) -> HCS_OP;
type PfnCloseOp = unsafe extern "system" fn(HCS_OP) -> HRES;
type PfnCreateCs = unsafe extern "system" fn(*const u16, *const u16, HCS_OP, *mut c_void, *mut HCS_CS) -> HRES;
type PfnStartCs = unsafe extern "system" fn(HCS_CS, HCS_OP, *const u16) -> HRES;
type PfnTerminateCs = unsafe extern "system" fn(HCS_CS, HCS_OP, *const u16) -> HRES;
type PfnCloseCs = unsafe extern "system" fn(HCS_CS) -> HRES;
type PfnWaitOp = unsafe extern "system" fn(HCS_OP, u32, *mut HRES) -> HRES;
type PfnGetProps = unsafe extern "system" fn(HCS_CS, *const u16, *mut *mut u16) -> HRES;

struct HcsApi {
    _module: *mut c_void,
    create_op: PfnCreateOp,
    close_op: PfnCloseOp,
    create_cs: PfnCreateCs,
    start_cs: PfnStartCs,
    terminate_cs: PfnTerminateCs,
    close_cs: PfnCloseCs,
    wait_op: PfnWaitOp,
    get_props: PfnGetProps,
}

unsafe impl Send for HcsApi {}
unsafe impl Sync for HcsApi {}

impl Drop for HcsApi {
    fn drop(&mut self) {
        if !self._module.is_null() {
            unsafe { FreeLibrary(self._module) };
        }
    }
}

static HCS_API: std::sync::OnceLock<Option<HcsApi>> = std::sync::OnceLock::new();

impl HcsApi {
    fn init() -> Result<&'static Self, String> {
        HCS_API
            .get_or_init(|| {
                let dll: Vec<u16> = "ComputeCore.dll\0".encode_utf16().collect();
                let hmod = unsafe { LoadLibraryW(dll.as_ptr()) };
                if hmod.is_null() {
                    return None;
                }
                macro_rules! load_fn {
                    ($n:expr, $t:ty) => {{
                        let a = unsafe { GetProcAddress(hmod, concat!($n, "\0").as_ptr()) };
                        if a.is_null() {
                            unsafe { FreeLibrary(hmod) };
                            return None;
                        }
                        unsafe { std::mem::transmute::<*mut c_void, $t>(a) }
                    }};
                }
                Some(HcsApi {
                    _module: hmod,
                    create_op: load_fn!("HcsCreateOperation", PfnCreateOp),
                    close_op: load_fn!("HcsCloseOperation", PfnCloseOp),
                    create_cs: load_fn!("HcsCreateComputeSystem", PfnCreateCs),
                    start_cs: load_fn!("HcsStartComputeSystem", PfnStartCs),
                    terminate_cs: load_fn!("HcsTerminateComputeSystem", PfnTerminateCs),
                    close_cs: load_fn!("HcsCloseComputeSystem", PfnCloseCs),
                    wait_op: load_fn!("HcsWaitForOperationResult", PfnWaitOp),
                    get_props: load_fn!("HcsGetComputeSystemProperties", PfnGetProps),
                })
            })
            .as_ref()
            .ok_or_else(|| "ComputeCore.dll not available".into())
    }

    fn create_compute_system(&self, id: &str, config_json: &str) -> Result<HCS_CS, String> {
        let id_w: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
        let cfg_w: Vec<u16> = config_json.encode_utf16().chain(std::iter::once(0)).collect();
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        if op.is_null() {
            return Err("HcsCreateOperation failed".into());
        }
        let mut handle: HCS_CS = ptr::null_mut();
        let hr = unsafe { (self.create_cs)(id_w.as_ptr(), cfg_w.as_ptr(), op, ptr::null_mut(), &mut handle) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return Err(format!("HcsCreateComputeSystem: 0x{hr:08X}"));
        }
        let mut op_res: HRES = 0;
        unsafe {
            (self.wait_op)(op, 30_000, &mut op_res);
            (self.close_op)(op)
        };
        Ok(handle)
    }

    fn start_compute_system(&self, handle: HCS_CS) -> Result<(), String> {
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        let hr = unsafe { (self.start_cs)(handle, op, ptr::null()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return Err(format!("HcsStartComputeSystem: 0x{hr:08X}"));
        }
        let mut op_res: HRES = 0;
        unsafe {
            (self.wait_op)(op, 30_000, &mut op_res);
            (self.close_op)(op)
        };
        Ok(())
    }

    fn terminate_compute_system(&self, handle: HCS_CS) -> Result<(), String> {
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        let hr = unsafe { (self.terminate_cs)(handle, op, ptr::null()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return Err(format!("terminate: 0x{hr:08X}"));
        }
        let mut op_res: HRES = 0;
        unsafe {
            (self.wait_op)(op, 10_000, &mut op_res);
            (self.close_op)(op)
        };
        Ok(())
    }

    fn close_compute_system(&self, handle: HCS_CS) {
        if !handle.is_null() {
            unsafe { (self.close_cs)(handle) };
        }
    }

    fn poll_state(&self, handle: HCS_CS) -> HcsState {
        let query: Vec<u16> = "{\"Property\":\"State\"}\0".encode_utf16().collect();
        let mut result_ptr: *mut u16 = ptr::null_mut();
        let hr = unsafe { (self.get_props)(handle, query.as_ptr(), &mut result_ptr) };
        if hr < 0 || result_ptr.is_null() {
            return HcsState::Error;
        }
        let json = unsafe {
            let mut len = 0;
            while *result_ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(result_ptr, len))
        };
        unsafe { LocalFree(result_ptr as *mut c_void) };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
            match v["State"].as_str() {
                Some("Running") => HcsState::Running,
                Some("Stopped") => HcsState::Stopped,
                _ => HcsState::Error,
            }
        } else {
            HcsState::Error
        }
    }
}

#[derive(Debug, PartialEq)]
enum HcsState {
    Running,
    Stopped,
    Error,
}

// ---------------------------------------------------------------------------
// VM config JSON
// ---------------------------------------------------------------------------

fn build_vm_json(
    _id: &str,
    kernel_path: &Path,
    initrd_path: &Path,
    rootfs_path: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> String {
    let kernel = kernel_path.to_string_lossy().replace('\\', "\\\\");
    let initrd = initrd_path.to_string_lossy().replace('\\', "\\\\");
    let share = rootfs_path.to_string_lossy().replace('\\', "\\\\");
    let args = format!("console=ttyS0 quiet loglevel=3 run={cmd_b64}");

    serde_json::json!({
        "SchemaVersion": { "Major": 2, "Minor": 0 },
        "Owner": "tokimo-sandbox-svc",
        "VirtualMachine": {
            "ComputeTopology": {
                "Memory": { "Backing": "Virtual", "SizeInMB": memory_mb },
                "Processor": { "Count": cpu_count, "Maximum": cpu_count, "Weight": 100 }
            },
            "Chipset": {
                "LinuxKernel": {
                    "KernelPath": kernel, "InitrdPath": initrd, "Arguments": args
                }
            },
            "Devices": {
                "Plan9": {
                    "Shares": [{ "Name": "work", "Path": share, "Port": 564, "Flags": 0 }]
                }
            },
            "StopOnGuestCrash": true
        }
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn send_json(pipe: *mut c_void, value: &serde_json::Value) {
    let json = value.to_string();
    let bytes = json.as_bytes();
    let len = bytes.len() as u32;
    let mut written: u32 = 0;
    unsafe {
        WriteFile(
            pipe,
            (&len as *const u32) as *const c_void,
            4,
            &mut written,
            ptr::null_mut(),
        );
        WriteFile(
            pipe,
            bytes.as_ptr() as *const c_void,
            len,
            &mut written,
            ptr::null_mut(),
        );
    }
}

fn send_error(pipe: *mut c_void, code: &str, message: &str) {
    send_json(
        pipe,
        &serde_json::json!({
            "kind": "Error", "id": "", "error": { "code": code, "message": message }
        }),
    );
}
