//! tokimo-sandbox-svc — Windows SYSTEM service for HCS VM management.
//!
//! On non-Windows platforms this binary is a no-op stub.
//!
//! Usage (Windows):
//!   tokimo-sandbox-svc --install     Install & start the service (needs admin)
//!   tokimo-sandbox-svc --uninstall   Stop & remove the service (needs admin)
//!   tokimo-sandbox-svc               Run as a Windows service (called by SCM)
//!   tokimo-sandbox-svc --console     Run pipe server in foreground (debugging)

#[cfg(target_os = "windows")]
mod imp {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED,
        GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FlushFileBuffers,
        PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    };


    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
        PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
        OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CREATE_SERVICE,
        SERVICE_AUTO_START, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONTROL_STOP,
        SERVICE_DELAYED_AUTO_START_INFO, SERVICE_NO_CHANGE, SERVICE_START, SERVICE_STOP,
        SERVICE_STATUS, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        StartServiceCtrlDispatcherW, StartServiceW,
    };
    use windows_sys::Win32::System::Threading::CreateThread;

    // ---------------------------------------------------------------------------
    // Error codes not exported by windows-sys
    // ---------------------------------------------------------------------------

    const ERROR_SERVICE_EXISTS: u32 = 1073;
    const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;

    // ---------------------------------------------------------------------------
    // App constants
    // ---------------------------------------------------------------------------

    const SERVICE_NAME: &str = "TokimoSandboxSvc";
    const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";
    const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BU)";
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    // ---------------------------------------------------------------------------
    // Entry point
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

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn is_invalid(h: HANDLE) -> bool {
        h == INVALID_HANDLE_VALUE
    }

    fn is_null_sc(h: SC_HANDLE) -> bool {
        h.is_null()
    }

    // ---------------------------------------------------------------------------
    // Install / uninstall
    // ---------------------------------------------------------------------------

    fn install_service() {
        let exe_path = std::env::current_exe().expect("current_exe");
        let exe_str = wide(&exe_path.to_string_lossy());
        let svc_name = wide(SERVICE_NAME);

        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
        if is_null_sc(scm) {
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

        if is_null_sc(svc) {
            let err = unsafe { GetLastError() };
            if err == ERROR_SERVICE_EXISTS {
                println!("Service already installed.");
            } else {
                eprintln!("CreateServiceW failed: {err}");
                unsafe { CloseServiceHandle(scm) };
                std::process::exit(1);
            }
        }

        if !is_null_sc(svc) {
            let mut delayed = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: 1 };
            unsafe {
                ChangeServiceConfig2W(
                    svc,
                    SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                    &mut delayed as *mut _ as *mut c_void,
                );
                StartServiceW(svc, 0, ptr::null());
                CloseServiceHandle(svc);
            }
        }
        unsafe { CloseServiceHandle(scm) };
        println!("Service installed and started: {SERVICE_NAME}");
    }

    fn uninstall_service() {
        let svc_name = wide(SERVICE_NAME);
        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
        if is_null_sc(scm) {
            eprintln!("OpenSCManagerW failed: {}", unsafe { GetLastError() });
            std::process::exit(1);
        }

        let svc = unsafe { OpenServiceW(scm, svc_name.as_ptr(), SERVICE_STOP) };
        if is_null_sc(svc) {
            let err = unsafe { GetLastError() };
            if err == ERROR_SERVICE_DOES_NOT_EXIST {
                println!("Service not installed.");
                unsafe { CloseServiceHandle(scm) };
                return;
            }
            eprintln!("OpenServiceW failed: {err}");
            unsafe { CloseServiceHandle(scm) };
            std::process::exit(1);
        }

        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) };
        println!("Service stop requested.");
        unsafe { CloseServiceHandle(svc) };

        let svc = unsafe { OpenServiceW(scm, svc_name.as_ptr(), SERVICE_START) };
        if !is_null_sc(svc) {
            if unsafe { DeleteService(svc) } == 0 {
                eprintln!("DeleteService failed: {}", unsafe { GetLastError() });
            } else {
                println!("Service deleted.");
            }
            unsafe { CloseServiceHandle(svc) };
        }
        unsafe { CloseServiceHandle(scm) };
    }

    // ---------------------------------------------------------------------------
    // Service runtime
    // ---------------------------------------------------------------------------

    static SHUTDOWN: AtomicBool = AtomicBool::new(false);

    fn run_service() {
        let mut svc_name = wide(SERVICE_NAME);
        let svc_name_ptr = svc_name.as_mut_ptr();

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
        // svc_name dropped here — kept alive until after dispatcher returns
    }

    unsafe extern "system" fn service_main_wrapper(dw_argc: u32, lp_argv: *mut windows_sys::core::PWSTR) {
        let _ = (dw_argc, lp_argv);
        pipe_server_loop();
    }

    fn pipe_server_loop() {
        let pipe_name = wide(PIPE_NAME);
        let sddl = wide(PIPE_SDDL);

        let mut sd_ptr: *mut c_void = ptr::null_mut();
        let mut sd_size: u32 = 0;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                &mut sd_size,
            )
        };
        if ok == 0 {
            eprintln!("SDDL conversion failed: {}", unsafe { GetLastError() });
            std::process::exit(1);
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr,
            bInheritHandle: 0,
        };

        println!("Tokimo Sandbox Service starting on {PIPE_NAME} (v{VERSION})");

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
                    &sa,
                )
            };

            if is_invalid(pipe) {
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

            spawn_worker(pipe);
        }

        if !sd_ptr.is_null() {
            unsafe { LocalFree(sd_ptr as HLOCAL) };
        }
    }

    fn spawn_worker(pipe: HANDLE) {
        extern "system" fn trampoline(param: *mut c_void) -> u32 {
            handle_client(param as HANDLE);
            0
        }
        let mut tid: u32 = 0;
        unsafe {
            let h = CreateThread(
                ptr::null(),
                0,
                Some(trampoline),
                pipe as *mut c_void as *const c_void,
                0,
                &mut tid,
            );
            if !is_invalid(h) {
                CloseHandle(h);
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Client handler
    // ---------------------------------------------------------------------------

    fn handle_client(pipe: HANDLE) {
        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        let mut bytes_read: u32 = 0;
        if unsafe {
            ReadFile(
                pipe,
                len_buf.as_mut_ptr(),
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
                payload.as_mut_ptr(),
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

    fn disconnect(pipe: HANDLE) {
        unsafe { FlushFileBuffers(pipe) };
        unsafe { DisconnectNamedPipe(pipe) };
        unsafe { CloseHandle(pipe) };
    }

    // ---------------------------------------------------------------------------
    // ExecVm handler
    // ---------------------------------------------------------------------------

    fn handle_exec_vm(pipe: HANDLE, request: &serde_json::Value) {
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

        let hcs = HcsApi::new();
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

    fn send_json(pipe: HANDLE, value: &serde_json::Value) {
        let json = value.to_string();
        let bytes = json.as_bytes();
        let len = bytes.len() as u32;
        let mut written: u32 = 0;
        unsafe {
            WriteFile(
                pipe,
                &len as *const u32 as *const u8,
                4,
                &mut written,
                ptr::null_mut(),
            );
            WriteFile(
                pipe,
                bytes.as_ptr(),
                len,
                &mut written,
                ptr::null_mut(),
            );
        }
    }

    fn send_error(pipe: HANDLE, code: &str, message: &str) {
        send_json(
            pipe,
            &serde_json::json!({
                "kind": "Error", "id": "", "error": { "code": code, "message": message }
            }),
        );
    }

    // ---------------------------------------------------------------------------
    // HCS API — via windows-sys (Win32::System::HostComputeSystem)
    // ---------------------------------------------------------------------------

    use windows_sys::Win32::System::HostComputeSystem::{
        HcsCloseComputeSystem, HcsCloseOperation, HcsCreateComputeSystem,
        HcsCreateOperation, HcsGetComputeSystemProperties, HcsStartComputeSystem,
        HcsTerminateComputeSystem, HcsWaitForOperationResult, HCS_OPERATION, HCS_SYSTEM,
    };

    struct HcsApi;

    impl HcsApi {
        fn new() -> Self {
            HcsApi
        }

        fn create_compute_system(&self, id: &str, config_json: &str) -> Result<HCS_SYSTEM, String> {
            let id_w: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
            let cfg_w: Vec<u16> = config_json.encode_utf16().chain(std::iter::once(0)).collect();
            let op = unsafe { HcsCreateOperation(ptr::null(), None) };
            if op.is_null() {
                return Err("HcsCreateOperation failed".into());
            }
            let mut system: HCS_SYSTEM = ptr::null_mut();
            let hr = unsafe { HcsCreateComputeSystem(id_w.as_ptr(), cfg_w.as_ptr(), op, ptr::null(), &mut system) };
            wait_op(op, hr, "HcsCreateComputeSystem")?;
            Ok(system)
        }

        fn start_compute_system(&self, handle: HCS_SYSTEM) -> Result<(), String> {
            let op = unsafe { HcsCreateOperation(ptr::null(), None) };
            let hr = unsafe { HcsStartComputeSystem(handle, op, ptr::null()) };
            wait_op(op, hr, "HcsStartComputeSystem")
        }

        fn terminate_compute_system(&self, handle: HCS_SYSTEM) -> Result<(), String> {
            let op = unsafe { HcsCreateOperation(ptr::null(), None) };
            let hr = unsafe { HcsTerminateComputeSystem(handle, op, ptr::null()) };
            wait_op(op, hr, "terminate")
        }

        fn close_compute_system(&self, handle: HCS_SYSTEM) {
            if !handle.is_null() {
                unsafe { HcsCloseComputeSystem(handle) };
            }
        }

        fn poll_state(&self, handle: HCS_SYSTEM) -> HcsState {
            let query: Vec<u16> = "{\"Property\":\"State\"}\0".encode_utf16().collect();
            let op = unsafe { HcsCreateOperation(ptr::null(), None) };
            let hr = unsafe { HcsGetComputeSystemProperties(handle, op, query.as_ptr()) };
            let mut result_ptr: windows_sys::core::PWSTR = ptr::null_mut();
            if hr < 0 {
                unsafe { HcsCloseOperation(op) };
                return HcsState::Error;
            }
            let wait_hr = unsafe { HcsWaitForOperationResult(op, 5_000, &mut result_ptr) };
            unsafe { HcsCloseOperation(op) };
            if wait_hr < 0 || result_ptr.is_null() {
                return HcsState::Error;
            }
            let json = unsafe {
                let mut len = 0;
                while *result_ptr.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(result_ptr, len))
            };
            unsafe { LocalFree(result_ptr as HLOCAL) };
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

    fn wait_op(op: HCS_OPERATION, hr: i32, label: &str) -> Result<(), String> {
        if hr < 0 {
            unsafe { HcsCloseOperation(op) };
            return Err(format!("{label}: 0x{hr:08X}"));
        }
        let mut result_ptr: windows_sys::core::PWSTR = ptr::null_mut();
        let wait_hr = unsafe { HcsWaitForOperationResult(op, 30_000, &mut result_ptr) };
        if !result_ptr.is_null() {
            unsafe { LocalFree(result_ptr as HLOCAL) };
        }
        unsafe { HcsCloseOperation(op) };
        if wait_hr < 0 {
            return Err(format!("{label} wait: 0x{wait_hr:08X}"));
        }
        Ok(())
    }

    #[derive(Debug, PartialEq)]
    enum HcsState {
        Running,
        Stopped,
        Error,
    }
} // end of mod imp

#[cfg(target_os = "windows")]
fn main() {
    imp::run();
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("tokimo-sandbox-svc is Windows-only");
    std::process::exit(1);
}
