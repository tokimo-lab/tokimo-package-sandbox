//! Windows-only implementation of the SYSTEM service.
//!
//! Persistent JSON-RPC dispatch over a named pipe. See `src/svc_protocol.rs`
//! for the wire format. Each connection runs in its own thread; per-connection
//! state holds the active `ConfigureParams`, HCS handle, `WinInitClient`, and
//! a map of running spawned children.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HLOCAL, HWND, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
    WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICONTEXT,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use tokimo_package_sandbox::canonicalize_safe;
use tokimo_package_sandbox::protocol::types::MountEntry;
use tokimo_package_sandbox::svc_protocol::{
    AddPlan9ShareParams, BoolValue, CreateDiskImageParams, ExecParams, ExecResultWire, Frame,
    IdParams, KillParams, MAX_FRAME_BYTES, PROTOCOL_VERSION, RemovePlan9ShareParams, RootfsSpec,
    RpcError, SpawnResult, WriteStdinParams, encode_frame, method,
};
use tokimo_package_sandbox::{ConfigureParams, NetworkPolicy, Plan9Share};

mod hcn;
mod hcs;
mod hvsock;
mod vhdx_pool;
mod vmconfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SERVICE_NAME: &str = "TokimoSandboxSvc";
const INSTALL_SERVICE_NAME: &str = "tokimo-sandbox-svc";
const SERVICE_DISPLAY: &str = "Tokimo Sandbox Service";
const PIPE_NAME: &str = r"\\.\pipe\tokimo-sandbox-svc";

const PIPE_SDDL_SERVICE: &str = "O:SYG:SYD:(A;;GA;;;SY)(A;;0x12019b;;;IU)";
const PIPE_SDDL_CONSOLE: &str = "D:(A;;GA;;;IU)";

const VERSION: &str = env!("CARGO_PKG_VERSION");

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Service-wide debug-logging toggle (controlled via the `setDebugLogging` RPC).
static DEBUG_LOGGING: AtomicBool = AtomicBool::new(false);

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
            "--service" => {}
            "-h" | "--help" => {
                println!("tokimo-sandbox-svc v{VERSION}");
                println!(
                    "Usage: tokimo-sandbox-svc [--install|--uninstall|--console|--service]"
                );
                return;
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(2);
            }
        }
    }

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
    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE,
    ) {
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
        account_name: None,
        account_password: None,
    };

    match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START) {
        Ok(svc) => {
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
        Err(e) => match ws_error_code(&e) {
            Some(1073) => println!("Service already installed: {INSTALL_SERVICE_NAME}"),
            Some(1078) => {
                eprintln!(
                    "Cannot create service '{INSTALL_SERVICE_NAME}': another service is using \
                     the same display name '{SERVICE_DISPLAY}' (ERROR_DUPLICATE_SERVICE_NAME 1078)."
                );
                std::process::exit(1);
            }
            _ => {
                eprintln!("CreateService failed: {}", format_ws_error(&e));
                std::process::exit(1);
            }
        },
    }
}

fn ws_error_code(e: &windows_service::Error) -> Option<i32> {
    use std::error::Error;
    e.source()
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .and_then(|io| io.raw_os_error())
}

fn format_ws_error(e: &windows_service::Error) -> String {
    match ws_error_code(e) {
        Some(code) => format!("{e} (os error {code})"),
        None => e.to_string(),
    }
}

fn uninstall_service() {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
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
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(200));
            if matches!(
                svc.query_status().map(|s| s.current_state),
                Ok(ServiceState::Stopped)
            ) {
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

fn build_security_attributes(
    console_mode: bool,
) -> std::io::Result<(SECURITY_ATTRIBUTES, SdGuard)> {
    let sddl_str = if console_mode {
        PIPE_SDDL_CONSOLE
    } else {
        PIPE_SDDL_SERVICE
    };
    let sddl = HSTRING::from(sddl_str);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &mut sd, None)
    }
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
        eprintln!("[svc] caller signature verification: log-only");
    }

    while !SHUTDOWN.load(Ordering::Relaxed) {
        let pipe = unsafe {
            CreateNamedPipeW(
                &pipe_name,
                PIPE_ACCESS_DUPLEX
                    | windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
                        FILE_FLAG_OVERLAPPED.0,
                    ),
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                Some(&mut sa as *mut _),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            eprintln!("[svc] CreateNamedPipeW failed: {:?}", unsafe {
                GetLastError()
            });
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }

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
        if connected.is_err() && last != 535 && last != 997 {
            let _ = unsafe { CloseHandle(connect_evt) };
            let _ = unsafe { CloseHandle(pipe) };
            continue;
        }
        if last == 997 {
            unsafe { WaitForSingleObject(connect_evt, u32::MAX) };
        }
        let _ = unsafe { CloseHandle(connect_evt) };

        let pipe_ptr = pipe.0 as usize;
        std::thread::spawn(move || {
            handle_client(HANDLE(pipe_ptr as *mut _));
        });
    }
}

// ---------------------------------------------------------------------------
// Client connection state
// ---------------------------------------------------------------------------

/// Per-spawned-child handle held by the service.
struct ChildEntry {
    /// Joiner for the per-child poller thread; dropped on `kill` so the
    /// thread can exit cleanly.
    _joiner: thread::JoinHandle<()>,
    /// Set to `true` once the child's exit has been observed and the
    /// `EV_EXIT` event sent.
    finished: Arc<AtomicBool>,
}

struct SessionState {
    config: Option<ConfigureParams>,
    hcs: Option<(Arc<hcs::HcsApi>, hcs::CsHandle, String /* vm_id */)>,
    init: Option<Arc<tokimo_package_sandbox::init_client::WinInitClient>>,
    /// Held for the lifetime of a running VM; dropped (deleting the
    /// per-session VHDX clone for ephemeral leases) on stopVm.
    vhdx: Option<vhdx_pool::VhdxLease>,
    children: HashMap<String, ChildEntry>,
    /// Plan9 shares currently attached to the VM. Keyed by share `name`.
    /// Includes both boot-time shares (immutable) and dynamically-added
    /// shares; only the latter are removable.
    active_shares: HashMap<String, ActiveShare>,
    /// HCN endpoint owned by this session (None when NetworkPolicy::Blocked).
    /// Drop deletes the endpoint, releasing the NAT mapping on the host.
    network_endpoint: Option<hcn::HcnEndpoint>,
    running: bool,
    guest_connected: bool,
}

struct ActiveShare {
    port: u32,
    /// True for shares attached at boot-time via `build_session_v2`; the
    /// dispatcher refuses `removePlan9Share` for these because the HCS
    /// schema rejects `Remove` on shares declared in the original config.
    boot_time: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            config: None,
            hcs: None,
            init: None,
            vhdx: None,
            children: HashMap::new(),
            active_shares: HashMap::new(),
            network_endpoint: None,
            running: false,
            guest_connected: false,
        }
    }
}

/// Shared per-connection bag — wrap the writer in a Mutex so background
/// poller threads can emit `EV_STDOUT` / `EV_EXIT` frames without racing
/// the main dispatch thread.
struct Connection {
    pipe: HANDLE,
    /// Serializes writes so multiple emitter threads can coexist.
    write_lock: Mutex<()>,
    state: Mutex<SessionState>,
    /// Monotonic counter for spawned child IDs.
    job_counter: AtomicU64,
}

// HANDLE is `*mut c_void` (not Send); we manually attest single-thread-of-write
// by way of `write_lock`. The pipe is owned exclusively by this connection.
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

// ---------------------------------------------------------------------------
// Connection entry point
// ---------------------------------------------------------------------------

fn handle_client(pipe: HANDLE) {
    let caller = caller_image_path(pipe);
    match &caller {
        Some(p) => eprintln!("[svc] client connected: {}", p.display()),
        None => eprintln!("[svc] client connected: <unknown caller>"),
    }

    if verify_caller_required() {
        match caller.as_deref().and_then(safe_canon_or_log) {
            Some(canon) => {
                if let Err(why) = verify_authenticode(&canon) {
                    eprintln!(
                        "[svc] REJECT unsigned/untrusted caller {}: {why}",
                        canon.display()
                    );
                    disconnect(pipe);
                    return;
                }
            }
            None => {
                eprintln!("[svc] REJECT caller: could not resolve image path");
                disconnect(pipe);
                return;
            }
        }
    }

    let conn = Arc::new(Connection {
        pipe,
        write_lock: Mutex::new(()),
        state: Mutex::new(SessionState::default()),
        job_counter: AtomicU64::new(0),
    });

    // Hello handshake.
    match read_frame(pipe) {
        Ok(Frame::Hello { version, peer, .. }) => {
            eprintln!("[svc] hello from {peer} (proto v{version})");
            if version != PROTOCOL_VERSION {
                eprintln!(
                    "[svc] protocol version mismatch: client={version}, svc={PROTOCOL_VERSION}"
                );
                let _ = send_frame(
                    &conn,
                    &Frame::Hello {
                        version: PROTOCOL_VERSION,
                        peer: format!("tokimo-sandbox-svc/{VERSION}"),
                        info: json!({ "error": "protocol_version_mismatch" }),
                    },
                );
                disconnect(pipe);
                return;
            }
            // Reply with our Hello.
            let _ = send_frame(
                &conn,
                &Frame::Hello {
                    version: PROTOCOL_VERSION,
                    peer: format!("tokimo-sandbox-svc/{VERSION}"),
                    info: json!({}),
                },
            );
        }
        Ok(other) => {
            eprintln!("[svc] expected Hello, got {other:?}");
            disconnect(pipe);
            return;
        }
        Err(e) => {
            eprintln!("[svc] failed to read Hello: {e}");
            disconnect(pipe);
            return;
        }
    }

    // Dispatch loop.
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                if DEBUG_LOGGING.load(Ordering::Relaxed) {
                    eprintln!("[svc] connection closed: {e}");
                }
                break;
            }
        };
        match frame {
            Frame::Request { id, method, params } => {
                let result = dispatch(&conn, &method, params);
                let resp = match result {
                    Ok(v) => Frame::Response {
                        id,
                        result: Some(v),
                        error: None,
                    },
                    Err(e) => Frame::Response {
                        id,
                        result: None,
                        error: Some(e),
                    },
                };
                if let Err(e) = send_frame(&conn, &resp) {
                    eprintln!("[svc] write response failed: {e}");
                    break;
                }
            }
            Frame::Hello { .. } => {
                // Spurious Hello — ignore.
            }
            Frame::Notification { .. } | Frame::Response { .. } | Frame::Event { .. } => {
                // Client shouldn't send these; ignore.
            }
        }
    }

    // Connection teardown — best-effort tear down VM if still up.
    {
        let mut st = conn.state.lock().expect("state lock");
        teardown_session(&mut st);
    }
    disconnect(pipe);
}

// ---------------------------------------------------------------------------
// Method dispatch
// ---------------------------------------------------------------------------

fn dispatch(conn: &Arc<Connection>, method_name: &str, params: Value) -> Result<Value, RpcError> {
    match method_name {
        method::PING => Ok(json!({ "version": VERSION })),

        method::CONFIGURE => handle_configure(conn, params),
        method::CREATE_VM => handle_create_vm(conn),
        method::START_VM => handle_start_vm(conn),
        method::STOP_VM => handle_stop_vm(conn),

        method::IS_RUNNING => Ok(json!(BoolValue {
            value: conn.state.lock().unwrap().running
        })),
        method::IS_GUEST_CONNECTED => Ok(json!(BoolValue {
            value: conn.state.lock().unwrap().guest_connected
        })),
        method::IS_PROCESS_RUNNING => {
            let p: IdParams = serde_json::from_value(params)
                .map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            let st = conn.state.lock().unwrap();
            let alive = st
                .children
                .get(&p.id)
                .map(|c| !c.finished.load(Ordering::Relaxed))
                .unwrap_or(false);
            Ok(json!(BoolValue { value: alive }))
        }

        method::EXEC => handle_exec(conn, params),
        method::SPAWN => handle_spawn(conn, params),
        method::WRITE_STDIN => handle_write_stdin(conn, params),
        method::KILL => handle_kill(conn, params),

        method::SUBSCRIBE => Ok(json!({})),

        method::CREATE_DISK_IMAGE => {
            let _p: CreateDiskImageParams = serde_json::from_value(params)
                .map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            // TODO: implement via Win32_Storage_Vhd CreateVirtualDiskW.
            Err(RpcError::new(
                "not_implemented",
                "create_disk_image not yet implemented",
            ))
        }

        method::SET_DEBUG_LOGGING => {
            let enabled = params
                .get("enabled")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            DEBUG_LOGGING.store(enabled, Ordering::Relaxed);
            Ok(json!({}))
        }
        method::IS_DEBUG_LOGGING_ENABLED => Ok(json!(BoolValue {
            value: DEBUG_LOGGING.load(Ordering::Relaxed)
        })),

        method::SEND_GUEST_RESPONSE => Err(RpcError::new(
            "not_implemented",
            "send_guest_response not yet implemented",
        )),

        method::ADD_PLAN9_SHARE => {
            let p: AddPlan9ShareParams = serde_json::from_value(params)
                .map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_add_plan9_share(conn, p)
        }
        method::REMOVE_PLAN9_SHARE => {
            let p: RemovePlan9ShareParams = serde_json::from_value(params)
                .map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_remove_plan9_share(conn, p)
        }

        other => Err(RpcError::new(
            "unknown_method",
            format!("unknown method: {other}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn handle_configure(conn: &Arc<Connection>, params: Value) -> Result<Value, RpcError> {
    let cfg: ConfigureParams = serde_json::from_value(params)
        .map_err(|e| RpcError::new("bad_params", format!("configure: {e}")))?;
    let mut st = conn.state.lock().unwrap();
    if st.running {
        return Err(RpcError::new(
            "already_running",
            "cannot reconfigure while VM is running",
        ));
    }
    st.config = Some(cfg);
    Ok(json!({}))
}

fn handle_create_vm(conn: &Arc<Connection>) -> Result<Value, RpcError> {
    // The Windows backend rolls VM creation into `start_vm` since HCS
    // requires the full configuration up front and we want the guest
    // available as soon as the call returns. `create_vm` is a no-op
    // sanity check that configure was called.
    let st = conn.state.lock().unwrap();
    if st.config.is_none() {
        return Err(RpcError::new(
            "not_configured",
            "configure() must be called before create_vm()",
        ));
    }
    Ok(json!({}))
}

fn handle_start_vm(conn: &Arc<Connection>) -> Result<Value, RpcError> {
    // Take a snapshot of config without holding the state lock during
    // the long-running boot path (we re-acquire to install state).
    let cfg = {
        let st = conn.state.lock().unwrap();
        if st.running {
            return Err(RpcError::new("already_running", "VM is already running"));
        }
        st.config
            .clone()
            .ok_or_else(|| RpcError::new("not_configured", "configure() not called"))?
    };

    // Allocate HCN endpoint when network policy requires guest egress.
    // Observed/Gated currently fall through to AllowAll (TODO: smoltcp
    // userspace netstack — see plan/windows-service-upgrade.md Phase 4).
    let net_endpoint = match cfg.network {
        NetworkPolicy::Blocked => None,
        NetworkPolicy::AllowAll => {
            let net = hcn::HcnNetwork::create_or_open_nat()
                .map_err(|e| RpcError::new("hcn_network", e))?;
            let ep = net
                .create_endpoint()
                .map_err(|e| RpcError::new("hcn_endpoint", e))?;
            Some(ep)
        }
    };
    let net_endpoint_id_str = net_endpoint.as_ref().map(|e| e.id_string());
    let net_endpoint_mac = net_endpoint.as_ref().map(|e| e.mac_string().to_string());

    let (kernel, initrd, rootfs_template) = resolve_vm_artifacts(&cfg)
        .map_err(|e| RpcError::new("bad_path", e))?;

    if cfg.plan9_shares.is_empty() {
        return Err(RpcError::new(
            "validation",
            "at least one plan9_share is required on Windows",
        ));
    }
    if cfg.plan9_shares.len() > 64 {
        return Err(RpcError::new(
            "validation",
            format!("too many plan9_shares: {} (max 64)", cfg.plan9_shares.len()),
        ));
    }

    // Canonicalise share host paths (TOCTOU-safe).
    let mut canon_shares: Vec<(PathBuf, &tokimo_package_sandbox::Plan9Share)> = Vec::new();
    for (i, s) in cfg.plan9_shares.iter().enumerate() {
        let canon = canonicalize_safe(&s.host_path).map_err(|e| {
            RpcError::new(
                "bad_path",
                format!("plan9_shares[{i}].host_path ({}): {e}", s.host_path.display()),
            )
        })?;
        canon_shares.push((canon, s));
    }

    let vm_id = format!(
        "tokimo-sess-{}-{}",
        std::process::id(),
        rand_session_suffix()
    );

    let scratch_dir: PathBuf = canon_shares[0].0.clone();
    let rootfs_spec = RootfsSpec::Ephemeral {
        template: rootfs_template.to_string_lossy().into_owned(),
    };
    let lease = vhdx_pool::acquire(&rootfs_spec, &scratch_dir, &vm_id).map_err(|e| match e {
        vhdx_pool::PoolError::Busy(p) => RpcError::new(
            "persistent_busy",
            format!("rootfs target busy: {}", p.display()),
        ),
        other => RpcError::new("vhdx_pool", other.to_string()),
    })?;

    let init_port = vmconfig::alloc_session_init_port();
    let init_svc_id = vmconfig::hvsock_service_id(init_port);
    ensure_hvsocket_service_registered(&init_svc_id, "Tokimo Sandbox Init")
        .map_err(|e| RpcError::new("hvsock_register", e))?;
    let init_svc_guid =
        parse_guid(&init_svc_id).map_err(|e| RpcError::new("guid", e))?;
    let init_listener = hvsock::listen_for_guest(hvsock::HV_GUID_WILDCARD, init_svc_guid)
        .map_err(|e| RpcError::new("hvsock_listen", e.to_string()))?;

    let share_ports: Vec<u32> = (0..canon_shares.len())
        .map(|_| vmconfig::alloc_share_port())
        .collect();
    let v2_shares: Vec<vmconfig::V2Share<'_>> = canon_shares
        .iter()
        .zip(share_ports.iter())
        .map(|((host_path, spec), port)| vmconfig::V2Share {
            host_path: host_path.as_path(),
            name: spec.name.as_str(),
            port: *port,
            read_only: spec.read_only,
        })
        .collect();

    let cfg_json = vmconfig::build_session_v2_ex(
        &vm_id,
        &kernel,
        &initrd,
        lease.path(),
        &v2_shares,
        cfg.memory_mb,
        cfg.cpu_count as usize,
        init_port,
        net_endpoint_id_str.as_deref(),
        net_endpoint_mac.as_deref(),
    );
    let _ = std::fs::write(r"C:\tokimo-debug\last-hcs-session-config.json", &cfg_json);

    let api = hcs::HcsApi::init().map_err(|e| RpcError::new("hcs_init", e))?;
    let cs = api
        .create_compute_system(&vm_id, &cfg_json)
        .map_err(|e| RpcError::new("hcs_create", e))?;
    if let Err(e) = api.start_compute_system(cs) {
        api.close_compute_system(cs);
        return Err(RpcError::new("hcs_start", e));
    }

    // Accept the guest's init connection.
    let hv = match hvsock::accept_guest(&init_listener, Duration::from_secs(60)) {
        Ok(s) => s,
        Err(e) => {
            let _ = api.terminate_compute_system(cs);
            api.close_compute_system(cs);
            return Err(RpcError::new("hvsock_accept", e.to_string()));
        }
    };
    drop(init_listener);

    let hv_writer = match hv.try_clone() {
        Ok(w) => w,
        Err(e) => {
            let _ = api.terminate_compute_system(cs);
            api.close_compute_system(cs);
            return Err(RpcError::new("hvsock_clone", e.to_string()));
        }
    };

    let init = match tokimo_package_sandbox::init_client::WinInitClient::with_transport(
        Box::new(hv_writer),
        Box::new(hv),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = api.terminate_compute_system(cs);
            api.close_compute_system(cs);
            return Err(RpcError::new("init_client", e.to_string()));
        }
    };
    init.hello()
        .map_err(|e| RpcError::new("init_hello", e.to_string()))?;

    // Send mount manifest so guest-side init can mount each Plan9 share.
    let manifest: Vec<MountEntry> = canon_shares
        .iter()
        .zip(share_ports.iter())
        .map(|((_host, spec), port)| MountEntry {
            vsock_port: *port,
            guest_path: spec.guest_path.to_string_lossy().into_owned(),
            aname: spec.name.clone(),
            read_only: spec.read_only,
        })
        .collect();
    init.send_mount_manifest(manifest)
        .map_err(|e| RpcError::new("mount_manifest", e.to_string()))?;

    // Install state.
    let init_arc = Arc::new(init);
    {
        let mut st = conn.state.lock().unwrap();
        st.hcs = Some((api.clone(), cs, vm_id.clone()));
        st.init = Some(init_arc);
        st.vhdx = Some(lease);
        st.network_endpoint = net_endpoint;
        st.running = true;
        st.guest_connected = true;
        // Record boot-time shares so dynamic add/remove can validate
        // name uniqueness and reject removal of the immutable ones.
        st.active_shares.clear();
        for ((_host, spec), port) in canon_shares.iter().zip(share_ports.iter()) {
            st.active_shares.insert(
                spec.name.clone(),
                ActiveShare {
                    port: *port,
                    boot_time: true,
                },
            );
        }
    }

    // Emit Ready + GuestConnected events.
    let _ = send_event(conn, method::EV_READY, json!({}));
    let _ = send_event(
        conn,
        method::EV_GUEST_CONNECTED,
        json!({ "connected": true }),
    );

    Ok(json!({}))
}

fn handle_stop_vm(conn: &Arc<Connection>) -> Result<Value, RpcError> {
    let mut st = conn.state.lock().unwrap();
    teardown_session(&mut st);
    Ok(json!({}))
}

fn teardown_session(st: &mut SessionState) {
    if let Some(init) = st.init.take() {
        let _ = init.shutdown();
    }
    if let Some((api, cs, _vm_id)) = st.hcs.take() {
        let _ = api.terminate_compute_system(cs);
        api.close_compute_system(cs);
    }
    st.children.clear();
    st.active_shares.clear();
    st.vhdx = None;
    // Drop endpoint AFTER the VM is terminated so HCS releases the NIC
    // reference before HCN tries to delete it.
    st.network_endpoint = None;
    st.running = false;
    st.guest_connected = false;
}

fn handle_exec(conn: &Arc<Connection>, params: Value) -> Result<Value, RpcError> {
    let p: ExecParams = serde_json::from_value(params)
        .map_err(|e| RpcError::new("bad_params", format!("exec: {e}")))?;
    let init = require_init(conn)?;
    let argv_refs: Vec<&str> = p.argv.iter().map(|s| s.as_str()).collect();
    let info = init
        .spawn_pipes(&argv_refs, &p.env, p.cwd.as_deref())
        .map_err(|e| RpcError::new("spawn", e.to_string()))?;

    if let Some(stdin) = &p.stdin {
        let _ = init.write(&info.child_id, stdin);
    }

    // Drain until exit. Use a reasonable timeout; long-running execs
    // should use spawn() instead.
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        for chunk in init.drain_stdout(&info.child_id) {
            stdout.extend_from_slice(&chunk);
        }
        for chunk in init.drain_stderr(&info.child_id) {
            stderr.extend_from_slice(&chunk);
        }
        if let Some((exit_code, signal)) = init.take_exit(&info.child_id) {
            // One last drain post-exit.
            for chunk in init.drain_stdout(&info.child_id) {
                stdout.extend_from_slice(&chunk);
            }
            for chunk in init.drain_stderr(&info.child_id) {
                stderr.extend_from_slice(&chunk);
            }
            let _ = init.close_child(&info.child_id);
            return Ok(serde_json::to_value(ExecResultWire {
                stdout,
                stderr,
                exit_code,
                signal,
            })
            .unwrap());
        }
        if Instant::now() >= deadline {
            let _ = init.signal(&info.child_id, 9, false);
            return Err(RpcError::new("timeout", "exec deadline exceeded"));
        }
        let _ = init.wait_for_event(&info.child_id, Instant::now() + Duration::from_millis(200));
    }
}

fn handle_spawn(conn: &Arc<Connection>, params: Value) -> Result<Value, RpcError> {
    let p: ExecParams = serde_json::from_value(params)
        .map_err(|e| RpcError::new("bad_params", format!("spawn: {e}")))?;
    let init = require_init(conn)?;
    let argv_refs: Vec<&str> = p.argv.iter().map(|s| s.as_str()).collect();
    let info = init
        .spawn_pipes(&argv_refs, &p.env, p.cwd.as_deref())
        .map_err(|e| RpcError::new("spawn", e.to_string()))?;
    let child_id = info.child_id.clone();

    if let Some(stdin) = &p.stdin {
        let _ = init.write(&child_id, stdin);
    }

    // Spawn a per-child poller thread that drains stdout/stderr/exit and
    // emits Event frames over the pipe.
    let conn_w = Arc::clone(conn);
    let init_w = Arc::clone(&init);
    let child_id_w = child_id.clone();
    let finished = Arc::new(AtomicBool::new(false));
    let finished_w = Arc::clone(&finished);
    let joiner = thread::spawn(move || {
        child_poller(conn_w, init_w, child_id_w, finished_w);
    });

    // Map our visible JobId to the init's child id (they're the same string here).
    {
        let mut st = conn.state.lock().unwrap();
        st.children.insert(
            child_id.clone(),
            ChildEntry {
                _joiner: joiner,
                finished,
            },
        );
    }

    // Bump counter for telemetry (not strictly used).
    conn.job_counter.fetch_add(1, Ordering::Relaxed);

    Ok(serde_json::to_value(SpawnResult { id: child_id }).unwrap())
}

fn child_poller(
    conn: Arc<Connection>,
    init: Arc<tokimo_package_sandbox::init_client::WinInitClient>,
    child_id: String,
    finished: Arc<AtomicBool>,
) {
    loop {
        for chunk in init.drain_stdout(&child_id) {
            let _ = send_event(
                &conn,
                method::EV_STDOUT,
                json!({ "id": child_id, "data": chunk }),
            );
        }
        for chunk in init.drain_stderr(&child_id) {
            let _ = send_event(
                &conn,
                method::EV_STDERR,
                json!({ "id": child_id, "data": chunk }),
            );
        }
        if let Some((exit_code, signal)) = init.take_exit(&child_id) {
            // Final drain.
            for chunk in init.drain_stdout(&child_id) {
                let _ = send_event(
                    &conn,
                    method::EV_STDOUT,
                    json!({ "id": child_id, "data": chunk }),
                );
            }
            for chunk in init.drain_stderr(&child_id) {
                let _ = send_event(
                    &conn,
                    method::EV_STDERR,
                    json!({ "id": child_id, "data": chunk }),
                );
            }
            let _ = send_event(
                &conn,
                method::EV_EXIT,
                json!({
                    "id": child_id,
                    "exit_code": exit_code,
                    "signal": signal,
                }),
            );
            let _ = init.close_child(&child_id);
            finished.store(true, Ordering::Relaxed);
            return;
        }
        if init.is_dead() {
            finished.store(true, Ordering::Relaxed);
            return;
        }
        // Cap polling frequency.
        let _ = init.wait_for_event(&child_id, Instant::now() + Duration::from_millis(250));
    }
}

fn handle_write_stdin(conn: &Arc<Connection>, params: Value) -> Result<Value, RpcError> {
    let p: WriteStdinParams = serde_json::from_value(params)
        .map_err(|e| RpcError::new("bad_params", format!("write_stdin: {e}")))?;
    let init = require_init(conn)?;
    init.write(&p.id, &p.data)
        .map_err(|e| RpcError::new("write", e.to_string()))?;
    Ok(json!({}))
}

fn handle_kill(conn: &Arc<Connection>, params: Value) -> Result<Value, RpcError> {
    let p: KillParams = serde_json::from_value(params)
        .map_err(|e| RpcError::new("bad_params", format!("kill: {e}")))?;
    let init = require_init(conn)?;
    init.signal(&p.id, p.signal, false)
        .map_err(|e| RpcError::new("kill", e.to_string()))?;
    Ok(json!({}))
}

fn handle_add_plan9_share(
    conn: &Arc<Connection>,
    p: AddPlan9ShareParams,
) -> Result<Value, RpcError> {
    let share: Plan9Share = p.share;
    if share.name.is_empty() {
        return Err(RpcError::new("validation", "share name must not be empty"));
    }
    // Snapshot what we need under the lock; release before long blocking
    // calls (HCS modify, init RPC).
    let (api, cs, init) = {
        let st = conn.state.lock().unwrap();
        if !st.running {
            return Err(RpcError::new(
                "vm_not_running",
                "VM is not running; call startVm() first",
            ));
        }
        if st.active_shares.contains_key(&share.name) {
            return Err(RpcError::new(
                "duplicate_share",
                format!("share {:?} already attached", share.name),
            ));
        }
        let (api, cs, _id) = st
            .hcs
            .as_ref()
            .ok_or_else(|| RpcError::new("vm_not_running", "no live HCS handle"))?
            .clone();
        let init = st
            .init
            .clone()
            .ok_or_else(|| RpcError::new("vm_not_running", "no init client"))?;
        (api, cs, init)
    };

    let canon = canonicalize_safe(&share.host_path).map_err(|e| {
        RpcError::new(
            "bad_path",
            format!("host_path ({}): {e}", share.host_path.display()),
        )
    })?;

    let port = vmconfig::alloc_plan9_port();
    let req_json = vmconfig::plan9_modify_request(&share.name, &canon, port, "Add");

    api.modify_compute_system(cs, &req_json)
        .map_err(|e| RpcError::new("hcs_modify", e))?;

    // Tell the guest to dial + mount the new share.
    let entry = MountEntry {
        vsock_port: port,
        guest_path: share.guest_path.to_string_lossy().into_owned(),
        aname: share.name.clone(),
        read_only: share.read_only,
    };
    if let Err(e) = init.add_mount(entry) {
        // Best-effort rollback: detach the share from the VM so the
        // host doesn't leak the Plan9 endpoint.
        let rollback = vmconfig::plan9_modify_request(&share.name, &canon, port, "Remove");
        let _ = api.modify_compute_system(cs, &rollback);
        return Err(RpcError::new("guest_mount", e.to_string()));
    }

    {
        let mut st = conn.state.lock().unwrap();
        st.active_shares.insert(
            share.name.clone(),
            ActiveShare {
                port,
                boot_time: false,
            },
        );
    }

    Ok(json!({}))
}

fn handle_remove_plan9_share(
    conn: &Arc<Connection>,
    p: RemovePlan9ShareParams,
) -> Result<Value, RpcError> {
    let name = p.name;
    if name.is_empty() {
        return Err(RpcError::new("validation", "share name must not be empty"));
    }

    let (api, cs, init, port) = {
        let st = conn.state.lock().unwrap();
        if !st.running {
            return Err(RpcError::new(
                "vm_not_running",
                "VM is not running; call startVm() first",
            ));
        }
        let entry = st.active_shares.get(&name).ok_or_else(|| {
            RpcError::new("unknown_share", format!("no share named {name:?}"))
        })?;
        if entry.boot_time {
            return Err(RpcError::new(
                "immutable_share",
                format!("share {name:?} was attached at boot and cannot be removed"),
            ));
        }
        let port = entry.port;
        let (api, cs, _id) = st
            .hcs
            .as_ref()
            .ok_or_else(|| RpcError::new("vm_not_running", "no live HCS handle"))?
            .clone();
        let init = st
            .init
            .clone()
            .ok_or_else(|| RpcError::new("vm_not_running", "no init client"))?;
        (api, cs, init, port)
    };

    // Unmount guest-side first so the kernel releases the 9p fd before
    // we tell HCS to tear down the host endpoint.
    if let Err(e) = init.remove_mount(&name) {
        return Err(RpcError::new("guest_unmount", e.to_string()));
    }

    // Path is irrelevant for Remove (HCS keys off Name+Port); pass an
    // empty placeholder.
    let req_json = vmconfig::plan9_modify_request(&name, std::path::Path::new(""), port, "Remove");
    if let Err(e) = api.modify_compute_system(cs, &req_json) {
        return Err(RpcError::new("hcs_modify", e));
    }

    {
        let mut st = conn.state.lock().unwrap();
        st.active_shares.remove(&name);
    }

    Ok(json!({}))
}

fn require_init(
    conn: &Arc<Connection>,
) -> Result<Arc<tokimo_package_sandbox::init_client::WinInitClient>, RpcError> {
    conn.state
        .lock()
        .unwrap()
        .init
        .clone()
        .ok_or_else(|| RpcError::new("vm_not_running", "VM is not running"))
}

// ---------------------------------------------------------------------------
// VM artifact discovery
// ---------------------------------------------------------------------------

fn resolve_vm_artifacts(cfg: &ConfigureParams) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let kernel = match &cfg.kernel_path {
        Some(p) => canonicalize_safe(p).map_err(|e| format!("kernel: {e}"))?,
        None => find_artifact("vmlinuz")?,
    };
    let initrd = match &cfg.initrd_path {
        Some(p) => canonicalize_safe(p).map_err(|e| format!("initrd: {e}"))?,
        None => find_artifact("initrd.img")?,
    };
    let rootfs = match &cfg.vhdx_path {
        Some(p) => canonicalize_safe(p).map_err(|e| format!("rootfs: {e}"))?,
        None => find_artifact("rootfs.vhdx")?,
    };
    Ok((kernel, initrd, rootfs))
}

fn find_artifact(name: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut dir = exe.parent().map(Path::to_path_buf);
    while let Some(d) = dir {
        let candidate = d.join("vm").join(name);
        if candidate.is_file() {
            return canonicalize_safe(&candidate).map_err(|e| e.to_string());
        }
        dir = d.parent().map(Path::to_path_buf);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut d = Some(cwd);
        while let Some(p) = d {
            let candidate = p.join("vm").join(name);
            if candidate.is_file() {
                return canonicalize_safe(&candidate).map_err(|e| e.to_string());
            }
            d = p.parent().map(Path::to_path_buf);
        }
    }
    Err(format!("could not locate vm/{name} (no env vars consulted)"))
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

fn read_frame(pipe: HANDLE) -> std::io::Result<Frame> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    read_exact(pipe, &mut payload)?;
    serde_json::from_slice(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}")))
}

fn send_frame(conn: &Arc<Connection>, frame: &Frame) -> std::io::Result<()> {
    let bytes = encode_frame(frame)?;
    let _g = conn.write_lock.lock().unwrap();
    write_all(conn.pipe, &bytes)
}

fn send_event(conn: &Arc<Connection>, method_name: &str, params: Value) -> std::io::Result<()> {
    send_frame(
        conn,
        &Frame::Event {
            method: method_name.into(),
            params,
        },
    )
}

fn create_event() -> std::io::Result<HANDLE> {
    let h = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
    Ok(h)
}

unsafe fn ov_read(pipe: HANDLE, buf: &mut [u8]) -> std::io::Result<u32> {
    let evt = create_event()?;
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = evt;
    let mut got: u32 = 0;
    let r = unsafe { ReadFile(pipe, Some(buf), Some(&mut got), Some(&mut ov)) };
    let last = unsafe { GetLastError() }.0;
    if r.is_err() {
        if last == 997 {
            unsafe { WaitForSingleObject(evt, u32::MAX) };
            let mut transferred: u32 = 0;
            let ok = unsafe {
                windows::Win32::System::IO::GetOverlappedResult(pipe, &ov, &mut transferred, false)
            };
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
            let ok = unsafe {
                windows::Win32::System::IO::GetOverlappedResult(pipe, &ov, &mut transferred, false)
            };
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "pipe closed",
            ));
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "pipe closed",
            ));
        }
        off += written as usize;
    }
    Ok(())
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
// Caller verification
// ---------------------------------------------------------------------------

fn verify_caller_required() -> bool {
    if std::env::var("TOKIMO_VERIFY_CALLER")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
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

fn ensure_hvsocket_service_registered(svc_guid: &str, friendly_name: &str) -> Result<(), String> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATE_KEY_DISPOSITION, REG_OPTION_NON_VOLATILE,
        REG_SZ, RegCloseKey, RegCreateKeyExW, RegSetValueExW,
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
    let wide: Vec<u16> = friendly_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    let r2 = unsafe { RegSetValueExW(hk, &value_name, None, REG_SZ, Some(bytes)) };

    let sd_name = HSTRING::from("SecurityDescriptor");
    let sd_str = "D:(A;;GA;;;WD)";
    let sd_wide: Vec<u16> = sd_str.encode_utf16().chain(std::iter::once(0)).collect();
    let sd_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(sd_wide.as_ptr() as *const u8, sd_wide.len() * 2) };
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
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
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
        dwStateAction: WINTRUST_DATA_STATE_ACTION(1),
        hWVTStateData: HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WINTRUST_DATA_UICONTEXT(1),
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

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

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
        data4[i] =
            u8::from_str_radix(&parts[3][i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    for i in 0..6 {
        data4[2 + i] =
            u8::from_str_radix(&parts[4][i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
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

// Suppress unused warnings for items kept around for future use.
#[allow(dead_code)]
fn _unused_compat() {}
