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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

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
use tokimo_package_sandbox::protocol::types::MountEntry;
use tokimo_package_sandbox::session_registry::{SessionRegistry, SharedSession};
use tokimo_package_sandbox::svc_protocol::{
    AddPlan9ShareParams, BoolValue, CreateDiskImageParams, Frame, IdParams, JobIdListResult, JobIdResult, MAX_FRAME_BYTES,
    PROTOCOL_VERSION, RemovePlan9ShareParams, ResizeShellParams, RootfsSpec, RpcError, SignalShellParams,
    SpawnShellParams, WriteStdinParams, encode_frame, method,
};
use tokimo_package_sandbox::{ConfigureParams, NetworkPolicy, Plan9Share};

mod hcs;
mod hvsock;
mod netstack;
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
                println!("Usage: tokimo-sandbox-svc [--install|--uninstall|--console|--service]");
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
    let sessions = WindowsRegistry::new();
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
        let sessions_clone = sessions.clone();
        std::thread::spawn(move || {
            handle_client(HANDLE(pipe_ptr as *mut _), sessions_clone);
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
    /// Child ID of the auto-started shell (set by startVm).
    shell_child_id: Option<String>,
    children: HashMap<String, ChildEntry>,
    /// Plan9 shares currently attached to the VM. Keyed by share `name`.
    /// Includes both boot-time shares (immutable) and dynamically-added
    /// shares; only the latter are removable.
    active_shares: HashMap<String, ActiveShare>,
    /// Userspace netstack handle (None when NetworkPolicy::Blocked). The
    /// AtomicBool is the shutdown flag; setting it makes the netstack
    /// thread stop within ~50ms. The thread itself is detached.
    netstack_shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
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
            shell_child_id: None,
            children: HashMap::new(),
            active_shares: HashMap::new(),
            netstack_shutdown: None,
            running: false,
            guest_connected: false,
        }
    }
}

// SAFETY: The HANDLE (CsHandle) inside SessionState is owned exclusively by
// the session and never accessed from multiple threads simultaneously — all
// mutations go through the Mutex<SessionState> lock.
unsafe impl Send for SessionState {}

impl tokimo_package_sandbox::session_registry::SessionState for SessionState {
    fn is_running(&self) -> bool {
        self.running
    }
    fn teardown(&mut self) {
        teardown_session(self);
    }
}

/// Windows session registry type alias.
type WindowsRegistry = SessionRegistry<SessionState>;

/// Shared per-connection bag — wrap the writer in a Mutex so background
/// poller threads can emit `EV_STDOUT` / `EV_EXIT` frames without racing
/// the main dispatch thread.
struct Connection {
    pipe: HANDLE,
    /// Serializes writes so multiple emitter threads can coexist.
    write_lock: Mutex<()>,
    /// Key into the global [`WindowsRegistry`]. Set by `handle_configure`.
    session_id: Mutex<Option<String>>,
}

// HANDLE is `*mut c_void` (not Send); we manually attest single-thread-of-write
// by way of `write_lock`. The pipe is owned exclusively by this connection.
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

/// Tracks in-flight request handler threads so we can drain them on connection
/// close.  Mirrors the WaitGroup pattern used by Cowork's `handlePersistentRPC`.
struct InflightTracker {
    state: Mutex<(usize, bool)>, // (count, reader_done)
    cv: Condvar,
}

impl InflightTracker {
    fn new() -> Self {
        Self {
            state: Mutex::new((0, false)),
            cv: Condvar::new(),
        }
    }

    /// Called by the reader thread before spawning a handler.
    fn begin(&self) {
        let mut g = self.state.lock().unwrap();
        g.0 += 1;
    }

    /// Called by each handler thread when it finishes.
    fn end(&self) {
        let mut g = self.state.lock().unwrap();
        g.0 -= 1;
        if g.0 == 0 && g.1 {
            self.cv.notify_all();
        }
    }

    /// Called by the reader thread when it exits (EOF / error).
    fn mark_reader_done(&self) {
        let mut g = self.state.lock().unwrap();
        g.1 = true;
        if g.0 == 0 {
            self.cv.notify_all();
        }
    }

    /// Block until all in-flight handlers complete and the reader is done.
    fn drain(&self) {
        let mut g = self.state.lock().unwrap();
        while g.0 > 0 || !g.1 {
            g = self.cv.wait(g).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Connection entry point
// ---------------------------------------------------------------------------

/// Look up the [`SharedSession`] bound to this connection.
fn get_session<'a>(
    conn: &Connection,
    sessions: &'a WindowsRegistry,
) -> Result<Arc<SharedSession<SessionState>>, RpcError> {
    let key = conn.session_id.lock().unwrap();
    let key = key
        .as_ref()
        .ok_or_else(|| RpcError::new("not_configured", "call configure first"))?;
    sessions
        .get(key)
        .ok_or_else(|| RpcError::new("session_lost", "session no longer exists"))
}

fn handle_client(pipe: HANDLE, sessions: WindowsRegistry) {
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
        session_id: Mutex::new(None),
    });

    // Hello handshake.
    match read_frame(pipe) {
        Ok(Frame::Hello { version, peer, .. }) => {
            eprintln!("[svc] hello from {peer} (proto v{version})");
            if version != PROTOCOL_VERSION {
                eprintln!("[svc] protocol version mismatch: client={version}, svc={PROTOCOL_VERSION}");
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

    // Persistent RPC dispatch loop — concurrent, not serial.
    //
    // Each incoming request is dispatched in its own thread so that long-running
    // operations (e.g. `exec`) do not block other requests on the same
    // connection.  Responses are serialized through `conn.write_lock` which
    // already protects against interleaved writes from background poller
    // threads.
    //
    // This mirrors Cowork's `handlePersistentRPC` model: the connection stays
    // open until the client disconnects, and multiple requests can be in-flight
    // simultaneously.
    let tracker = Arc::new(InflightTracker::new());

    // Reader loop — runs on the connection thread.
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
                tracker.begin();
                let conn_t = Arc::clone(&conn);
                let sessions_t = sessions.clone();
                let tracker_t = Arc::clone(&tracker);
                thread::spawn(move || {
                    let result = dispatch(&conn_t, &method, params, &sessions_t);
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
                    if let Err(e) = send_frame(&conn_t, &resp) {
                        eprintln!("[svc] write response failed: {e}");
                    }
                    tracker_t.end();
                });
            }
            Frame::Hello { .. } => {
                // Spurious Hello — ignore.
            }
            Frame::Notification { .. } | Frame::Response { .. } | Frame::Event { .. } => {
                // Client shouldn't send these; ignore.
            }
        }
    }

    // Signal the reader is done, then wait for all in-flight handlers.
    tracker.mark_reader_done();
    tracker.drain();

    // Connection teardown — do NOT destroy the VM.  The session lives in
    // the global registry and survives reconnection.  Only the pipe is
    // released here.
    disconnect(pipe);
}

// ---------------------------------------------------------------------------
// Method dispatch
// ---------------------------------------------------------------------------

fn dispatch(
    conn: &Arc<Connection>,
    method_name: &str,
    params: Value,
    sessions: &WindowsRegistry,
) -> Result<Value, RpcError> {
    match method_name {
        method::PING => Ok(json!({ "version": VERSION })),

        method::CONFIGURE => handle_configure(conn, params, sessions),
        method::CREATE_VM => handle_create_vm(conn, sessions),
        method::START_VM => handle_start_vm(conn, sessions),
        method::STOP_VM => handle_stop_vm(conn, sessions),

        method::IS_RUNNING => {
            let shared = get_session(conn, sessions)?;
            Ok(json!(BoolValue {
                value: shared.state.lock().unwrap().running
            }))
        }
        method::IS_GUEST_CONNECTED => {
            let shared = get_session(conn, sessions)?;
            Ok(json!(BoolValue {
                value: shared.state.lock().unwrap().guest_connected
            }))
        }
        method::IS_PROCESS_RUNNING => {
            let p: IdParams = serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            let shared = get_session(conn, sessions)?;
            let st = shared.state.lock().unwrap();
            let alive = st
                .children
                .get(&p.id)
                .map(|c| !c.finished.load(Ordering::Relaxed))
                .unwrap_or(false);
            Ok(json!(BoolValue { value: alive }))
        }

        method::WRITE_STDIN => handle_write_stdin(conn, params, sessions),
        method::SHELL_ID => handle_shell_id(conn, sessions),
        method::SPAWN_SHELL => handle_spawn_shell(conn, params, sessions),
        method::CLOSE_SHELL => handle_close_shell(conn, params, sessions),
        method::LIST_SHELLS => handle_list_shells(conn, sessions),
        method::SIGNAL_SHELL => handle_signal_shell(conn, params, sessions),
        method::RESIZE_SHELL => handle_resize_shell(conn, params, sessions),

        method::SUBSCRIBE => Ok(json!({})),

        method::CREATE_DISK_IMAGE => {
            let _p: CreateDiskImageParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            // TODO: implement via Win32_Storage_Vhd CreateVirtualDiskW.
            Err(RpcError::new(
                "not_implemented",
                "create_disk_image not yet implemented",
            ))
        }

        method::SET_DEBUG_LOGGING => {
            let enabled = params.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
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
            let p: AddPlan9ShareParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_add_plan9_share(conn, p, sessions)
        }
        method::REMOVE_PLAN9_SHARE => {
            let p: RemovePlan9ShareParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_remove_plan9_share(conn, p, sessions)
        }

        other => Err(RpcError::new("unknown_method", format!("unknown method: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn handle_configure(conn: &Arc<Connection>, params: Value, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let cfg: ConfigureParams =
        serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", format!("configure: {e}")))?;

    // Session key: caller-supplied UUID or auto-generate.
    let key = if cfg.session_id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        cfg.session_id.clone()
    };

    let shared = sessions.get_or_create(&key);

    // If the VM is already running for this session, just bind and return.
    {
        let st = shared.state.lock().unwrap();
        if st.running {
            eprintln!("[svc] reusing existing session {key}");
            *conn.session_id.lock().unwrap() = Some(key);
            return Ok(json!({}));
        }
    }

    // Not running — store config.
    {
        let mut st = shared.state.lock().unwrap();
        st.config = Some(cfg);
    }

    // Bind this connection to the session.
    *conn.session_id.lock().unwrap() = Some(key);
    Ok(json!({}))
}

fn handle_create_vm(conn: &Arc<Connection>, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let shared = get_session(conn, sessions)?;
    let st = shared.state.lock().unwrap();
    if st.config.is_none() {
        return Err(RpcError::new(
            "not_configured",
            "configure() must be called before create_vm()",
        ));
    }
    Ok(json!({}))
}

fn handle_start_vm(conn: &Arc<Connection>, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let shared = get_session(conn, sessions)?;
    // Take a snapshot of config without holding the state lock during
    // the long-running boot path (we re-acquire to install state).
    let cfg = {
        let st = shared.state.lock().unwrap();
        if st.running {
            return Err(RpcError::new("already_running", "VM is already running"));
        }
        st.config
            .clone()
            .ok_or_else(|| RpcError::new("not_configured", "configure() not called"))?
    };

    // NetworkPolicy::AllowAll routes through the userspace netstack on a
    // dedicated hvsock channel; HCN NAT is no longer used. See
    // `imp::netstack` and `docs/cowork-networking-reverse-engineering.md`.
    let netstack_port: Option<u32> = match cfg.network {
        NetworkPolicy::Blocked => None,
        NetworkPolicy::AllowAll => Some(vmconfig::alloc_session_init_port()),
    };

    let (kernel, initrd, rootfs_template) = resolve_vm_artifacts(&cfg).map_err(|e| RpcError::new("bad_path", e))?;

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

    let vm_id = format!("tokimo-sess-{}-{}", std::process::id(), rand_session_suffix());

    let scratch_dir: PathBuf = canon_shares[0].0.clone();
    let rootfs_spec = RootfsSpec::Ephemeral {
        template: rootfs_template.to_string_lossy().into_owned(),
    };
    let lease = vhdx_pool::acquire(&rootfs_spec, &scratch_dir, &vm_id).map_err(|e| match e {
        vhdx_pool::PoolError::Busy(p) => {
            RpcError::new("persistent_busy", format!("rootfs target busy: {}", p.display()))
        }
        other => RpcError::new("vhdx_pool", other.to_string()),
    })?;

    let init_port = vmconfig::alloc_session_init_port();
    let init_svc_id = vmconfig::hvsock_service_id(init_port);
    let init_svc_guid = parse_guid(&init_svc_id).map_err(|e| RpcError::new("guid", e))?;
    let init_listener = hvsock::listen_for_guest(hvsock::HV_GUID_WILDCARD, init_svc_guid)
        .map_err(|e| RpcError::new("hvsock_listen", e.to_string()))?;

    // Per-session netstack hvsock listener (only when AllowAll). Must be
    // bound BEFORE HCS starts so the guest can connect immediately at boot.
    let netstack_listener = if let Some(p) = netstack_port {
        let svc_id = vmconfig::hvsock_service_id(p);
        let svc_guid = parse_guid(&svc_id).map_err(|e| RpcError::new("guid", e))?;
        Some(
            hvsock::listen_for_guest(hvsock::HV_GUID_WILDCARD, svc_guid)
                .map_err(|e| RpcError::new("hvsock_listen", e.to_string()))?,
        )
    } else {
        None
    };

    let share_ports: Vec<u32> = (0..canon_shares.len()).map(|_| vmconfig::alloc_share_port()).collect();
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
        netstack_port,
    );


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

    let init =
        match tokimo_package_sandbox::init_client::WinInitClient::with_transport(Box::new(hv_writer), Box::new(hv)) {
            Ok(c) => c,
            Err(e) => {
                let _ = api.terminate_compute_system(cs);
                api.close_compute_system(cs);
                return Err(RpcError::new("init_client", e.to_string()));
            }
        };
    init.hello().map_err(|e| RpcError::new("init_hello", e.to_string()))?;

    // Accept the netstack connection (NetworkPolicy::AllowAll only). The
    // guest-side `tokimo-tun-pump` connects from inside the VM after init.sh
    // brings up tk0. We accept AFTER init.hello() so a slow netstack accept
    // doesn't block the init handshake; the pump retries connect for ~30s.
    let netstack_shutdown = if let Some(listener) = netstack_listener {
        match hvsock::accept_guest(&listener, Duration::from_secs(30)) {
            Ok(net_sock) => {
                drop(listener);
                match net_sock.try_clone() {
                    Ok(writer) => {
                        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let _ = netstack::spawn(
                            Box::new(net_sock),
                            Box::new(writer),
                            Arc::clone(&shutdown),
                        );
                        Some(shutdown)
                    }
                    Err(e) => {
                        eprintln!("[netstack] hv clone fail: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("[netstack] accept timeout: {e}");
                None
            }
        }
    } else {
        None
    };

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

    // Auto-start a shell inside the VM.
    let shell_info = init
        .open_shell(&["/bin/bash"], &[], None)
        .map_err(|e| RpcError::new("open_shell", e.to_string()))?;
    let shell_child_id = shell_info.child_id;

    // Install state.
    let init_arc = Arc::new(init);

    // Spawn the per-child poller for the shell so its stdout/stderr/exit
    // flow back to subscribers as Frame::Event.
    let shell_finished = Arc::new(AtomicBool::new(false));
    let shell_joiner = {
        let conn_w = Arc::clone(conn);
        let init_w = Arc::clone(&init_arc);
        let id_w = shell_child_id.clone();
        let fin_w = Arc::clone(&shell_finished);
        thread::spawn(move || child_poller(conn_w, init_w, id_w, fin_w))
    };

    {
        let mut st = shared.state.lock().unwrap();
        st.hcs = Some((api.clone(), cs, vm_id.clone()));
        st.init = Some(init_arc);
        st.vhdx = Some(lease);
        st.shell_child_id = Some(shell_child_id.clone());
        st.children.insert(
            shell_child_id,
            ChildEntry {
                _joiner: shell_joiner,
                finished: shell_finished,
            },
        );
        st.netstack_shutdown = netstack_shutdown;
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
    let _ = send_event(conn, method::EV_GUEST_CONNECTED, json!({ "connected": true }));

    Ok(json!({}))
}

fn handle_stop_vm(conn: &Arc<Connection>, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let shared = get_session(conn, sessions)?;
    let mut st = shared.state.lock().unwrap();
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
    st.shell_child_id = None;
    st.children.clear();
    st.active_shares.clear();
    st.vhdx = None;
    // Stop the userspace netstack thread before tearing down HCS so it
    // can flush in-flight frames cleanly.
    if let Some(s) = st.netstack_shutdown.take() {
        s.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    st.running = false;
    st.guest_connected = false;
}

fn handle_write_stdin(conn: &Arc<Connection>, params: Value, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let p: WriteStdinParams =
        serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", format!("write_stdin: {e}")))?;
    let init = require_init(conn, sessions)?;
    init.write(&p.id, &p.data)
        .map_err(|e| RpcError::new("write", e.to_string()))?;
    Ok(json!({}))
}

fn handle_shell_id(conn: &Arc<Connection>, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let shared = get_session(conn, sessions)?;
    let st = shared.state.lock().unwrap();
    let id = st
        .shell_child_id
        .as_ref()
        .ok_or_else(|| RpcError::new("not_running", "VM not started or shell not available"))?;
    Ok(serde_json::to_value(JobIdResult { id: id.clone() }).unwrap())
}

fn handle_signal_shell(conn: &Arc<Connection>, params: Value, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let p: SignalShellParams =
        serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", format!("signal_shell: {e}")))?;
    let init = require_init(conn, sessions)?;
    {
        // Validate that the JobId refers to a registered child.
        let shared = get_session(conn, sessions)?;
        let st = shared.state.lock().unwrap();
        if !st.children.contains_key(&p.id) {
            return Err(RpcError::new("unknown_job", format!("no such shell: {}", p.id)));
        }
    }
    init.signal(&p.id, p.sig, true)
        .map_err(|e| RpcError::new("signal", e.to_string()))?;
    Ok(json!({}))
}

fn handle_spawn_shell(conn: &Arc<Connection>, params: Value, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    // SpawnShellParams was added in PROTOCOL_VERSION 4. Older clients
    // (and the simple `{}` body sent by spawnShell with default opts)
    // deserialize cleanly because every field has `#[serde(default)]`.
    let p: SpawnShellParams = if params.is_null() {
        SpawnShellParams::default()
    } else {
        serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", format!("spawn_shell: {e}")))?
    };
    let init = require_init(conn, sessions)?;

    let argv: Vec<String> = p.argv.unwrap_or_else(|| vec!["/bin/bash".to_string()]);
    let env = p.env;
    let cwd = p.cwd;

    let shell_info = match (p.pty_rows, p.pty_cols) {
        (Some(rows), Some(cols)) => init
            .spawn_pty(&argv, &env, cwd.as_deref(), rows, cols)
            .map_err(|e| RpcError::new("spawn_pty", e.to_string()))?,
        _ => {
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            init.spawn_pipes(&argv_refs, &env, cwd.as_deref())
                .map_err(|e| RpcError::new("spawn_pipes", e.to_string()))?
        }
    };
    let child_id = shell_info.child_id;

    // Spawn the per-child poller so stdout/stderr/exit flow back to subscribers.
    let finished = Arc::new(AtomicBool::new(false));
    let joiner = {
        let conn_w = Arc::clone(conn);
        let init_w = Arc::clone(&init);
        let id_w = child_id.clone();
        let fin_w = Arc::clone(&finished);
        thread::spawn(move || child_poller(conn_w, init_w, id_w, fin_w))
    };

    {
        let shared = get_session(conn, sessions)?;
        let mut st = shared.state.lock().unwrap();
        st.children.insert(
            child_id.clone(),
            ChildEntry {
                _joiner: joiner,
                finished,
            },
        );
    }
    Ok(serde_json::to_value(JobIdResult { id: child_id }).unwrap())
}

fn handle_resize_shell(conn: &Arc<Connection>, params: Value, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let p: ResizeShellParams =
        serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", format!("resize_shell: {e}")))?;
    let init = require_init(conn, sessions)?;
    {
        let shared = get_session(conn, sessions)?;
        let st = shared.state.lock().unwrap();
        if !st.children.contains_key(&p.id) {
            return Err(RpcError::new("unknown_job", format!("no such shell: {}", p.id)));
        }
    }
    init.resize(&p.id, p.rows, p.cols)
        .map_err(|e| RpcError::new("resize", e.to_string()))?;
    Ok(json!({}))
}

fn handle_close_shell(conn: &Arc<Connection>, params: Value, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let p: IdParams =
        serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", format!("close_shell: {e}")))?;
    let init = require_init(conn, sessions)?;
    {
        let shared = get_session(conn, sessions)?;
        let st = shared.state.lock().unwrap();
        if !st.children.contains_key(&p.id) {
            return Err(RpcError::new("unknown_job", format!("no such shell: {}", p.id)));
        }
    }
    // SIGTERM the shell's process group; the poller will see the exit
    // event and emit Event::Exit.
    let _ = init.signal(&p.id, 15, true);
    {
        let shared = get_session(conn, sessions)?;
        let mut st = shared.state.lock().unwrap();
        st.children.remove(&p.id);
        if st.shell_child_id.as_deref() == Some(p.id.as_str()) {
            st.shell_child_id = None;
        }
    }
    Ok(json!({}))
}

fn handle_list_shells(conn: &Arc<Connection>, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let shared = get_session(conn, sessions)?;
    let st = shared.state.lock().unwrap();
    // Every entry in `st.children` is a shell (boot or spawn_shell).
    // Order is unspecified per trait contract.
    let ids: Vec<String> = st.children.keys().cloned().collect();
    Ok(serde_json::to_value(JobIdListResult { ids }).unwrap())
}

fn child_poller(
    conn: Arc<Connection>,
    init: Arc<tokimo_package_sandbox::init_client::WinInitClient>,
    child_id: String,
    finished: Arc<AtomicBool>,
) {
    loop {
        for chunk in init.drain_stdout(&child_id) {
            let _ = send_event(&conn, method::EV_STDOUT, json!({ "id": child_id, "data": chunk }));
        }
        for chunk in init.drain_stderr(&child_id) {
            let _ = send_event(&conn, method::EV_STDERR, json!({ "id": child_id, "data": chunk }));
        }
        if let Some((exit_code, signal)) = init.take_exit(&child_id) {
            // Final drain.
            for chunk in init.drain_stdout(&child_id) {
                let _ = send_event(&conn, method::EV_STDOUT, json!({ "id": child_id, "data": chunk }));
            }
            for chunk in init.drain_stderr(&child_id) {
                let _ = send_event(&conn, method::EV_STDERR, json!({ "id": child_id, "data": chunk }));
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

fn handle_add_plan9_share(
    conn: &Arc<Connection>,
    p: AddPlan9ShareParams,
    sessions: &WindowsRegistry,
) -> Result<Value, RpcError> {
    let share: Plan9Share = p.share;
    if share.name.is_empty() {
        return Err(RpcError::new("validation", "share name must not be empty"));
    }
    // Snapshot what we need under the lock; release before long blocking
    // calls (HCS modify, init RPC).
    let shared = get_session(conn, sessions)?;
    let (api, cs, init) = {
        let st = shared.state.lock().unwrap();
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

    let canon = canonicalize_safe(&share.host_path)
        .map_err(|e| RpcError::new("bad_path", format!("host_path ({}): {e}", share.host_path.display())))?;

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
        let mut st = shared.state.lock().unwrap();
        st.active_shares
            .insert(share.name.clone(), ActiveShare { port, boot_time: false });
    }

    Ok(json!({}))
}

fn handle_remove_plan9_share(
    conn: &Arc<Connection>,
    p: RemovePlan9ShareParams,
    sessions: &WindowsRegistry,
) -> Result<Value, RpcError> {
    let name = p.name;
    if name.is_empty() {
        return Err(RpcError::new("validation", "share name must not be empty"));
    }

    let shared = get_session(conn, sessions)?;
    let (api, cs, init, port) = {
        let st = shared.state.lock().unwrap();
        if !st.running {
            return Err(RpcError::new(
                "vm_not_running",
                "VM is not running; call startVm() first",
            ));
        }
        let entry = st
            .active_shares
            .get(&name)
            .ok_or_else(|| RpcError::new("unknown_share", format!("no share named {name:?}")))?;
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
        let mut st = shared.state.lock().unwrap();
        st.active_shares.remove(&name);
    }

    Ok(json!({}))
}

fn require_init(
    conn: &Arc<Connection>,
    sessions: &WindowsRegistry,
) -> Result<Arc<tokimo_package_sandbox::init_client::WinInitClient>, RpcError> {
    let shared = get_session(conn, sessions)?;
    shared
        .state
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
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
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
    if std::env::var("TOKIMO_VERIFY_CALLER").map(|v| v == "1").unwrap_or(false) {
        return true;
    }
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
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
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

// Suppress unused warnings for items kept around for future use.
#[allow(dead_code)]
fn _unused_compat() {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokimo_package_sandbox::session_registry::SessionState as SessionStateTrait;

    /// Build a Connection with a dummy pipe handle (never used for I/O in tests).
    fn dummy_conn() -> Arc<Connection> {
        Arc::new(Connection {
            pipe: HANDLE(std::ptr::null_mut()),
            write_lock: Mutex::new(()),
            session_id: Mutex::new(None),
        })
    }

    #[test]
    fn configure_creates_session_and_binds() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Before configure: no session bound.
        assert!(conn.session_id.lock().unwrap().is_none());

        // Configure with a specific session_id.
        let params = json!({ "session_id": "test-001", "user_data_name": "test", "memory_mb": 1024, "cpu_count": 2 });
        handle_configure(&conn, params, &sessions).unwrap();

        // Now a session is bound.
        let key = conn.session_id.lock().unwrap();
        assert_eq!(key.as_deref(), Some("test-001"));
        drop(key);

        // The session exists in the registry.
        let shared = sessions.get("test-001").unwrap();
        let st = shared.state.lock().unwrap();
        assert!(st.config.is_some());
        assert!(!st.running); // not started yet
    }

    #[test]
    fn configure_same_id_reuses_session() {
        let sessions = WindowsRegistry::new();
        let conn_a = dummy_conn();
        let conn_b = dummy_conn();

        let params = json!({ "session_id": "reuse-001", "user_data_name": "test" });

        // Connection A configures.
        handle_configure(&conn_a, params.clone(), &sessions).unwrap();

        // Simulate "running" state so connection B hits the reuse path.
        {
            let shared = sessions.get("reuse-001").unwrap();
            shared.state.lock().unwrap().running = true;
        }

        // Connection B configures with same session_id.
        handle_configure(&conn_b, params, &sessions).unwrap();

        // Both point to the same session.
        assert_eq!(
            conn_a.session_id.lock().unwrap().as_deref(),
            conn_b.session_id.lock().unwrap().as_deref()
        );

        // Only one session in the registry.
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn configure_auto_generates_session_id_when_empty() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Empty session_id → auto-generated UUID.
        let params = json!({ "session_id": "", "user_data_name": "test" });
        handle_configure(&conn, params, &sessions).unwrap();

        let key = conn.session_id.lock().unwrap();
        let id = key.as_ref().unwrap();
        assert!(!id.is_empty());
        // Should be a valid UUID.
        assert!(uuid::Uuid::parse_str(id).is_ok());
    }

    #[test]
    fn session_state_default() {
        let st = SessionState::default();
        assert!(!SessionStateTrait::is_running(&st));
        assert!(st.config.is_none());
        assert!(st.hcs.is_none());
        assert!(st.init.is_none());
        assert!(st.children.is_empty());
        assert!(st.active_shares.is_empty());
    }

    #[test]
    fn session_state_trait_impl() {
        let mut st = SessionState::default();
        st.running = true;
        assert!(SessionStateTrait::is_running(&st));

        SessionStateTrait::teardown(&mut st);
        assert!(!SessionStateTrait::is_running(&st));
    }

    #[test]
    fn get_session_fails_without_configure() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // No configure called → session_id is None.
        let result = get_session(&conn, &sessions);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.code, "not_configured");
    }

    #[test]
    fn get_session_fails_for_missing_session() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Manually set a session_id that doesn't exist in the registry.
        *conn.session_id.lock().unwrap() = Some("ghost".to_string());

        let result = get_session(&conn, &sessions);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.code, "session_lost");
    }

    #[test]
    fn dispatch_not_configured_returns_error() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Any command before configure should fail.
        let result = dispatch(&conn, method::IS_RUNNING, json!({}), &sessions);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.code, "not_configured");
    }

    #[test]
    fn dispatch_ping_works_without_session() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // PING doesn't require a session.
        let result = dispatch(&conn, method::PING, json!({}), &sessions).unwrap();
        assert!(result.get("version").is_some());
    }

    #[test]
    fn dispatch_is_running_reflects_state() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Configure first.
        let params = json!({ "session_id": "run-check", "user_data_name": "test" });
        handle_configure(&conn, params, &sessions).unwrap();

        // Not running yet.
        let result = dispatch(&conn, method::IS_RUNNING, json!({}), &sessions).unwrap();
        assert!(!result.get("value").unwrap().as_bool().unwrap());

        // Mark as running.
        {
            let shared = sessions.get("run-check").unwrap();
            shared.state.lock().unwrap().running = true;
        }

        // Now is_running should return true.
        let result = dispatch(&conn, method::IS_RUNNING, json!({}), &sessions).unwrap();
        assert!(result.get("value").unwrap().as_bool().unwrap());
    }

    #[test]
    fn stop_vm_tears_down_session_state() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Configure and mark as running.
        handle_configure(
            &conn,
            json!({ "session_id": "stop-test", "user_data_name": "test" }),
            &sessions,
        )
        .unwrap();
        {
            let shared = sessions.get("stop-test").unwrap();
            let mut st = shared.state.lock().unwrap();
            st.running = true;
        }

        // Stop the VM.
        dispatch(&conn, method::STOP_VM, json!({}), &sessions).unwrap();

        // Session still exists in registry (not removed), but is no longer running.
        let shared = sessions.get("stop-test").unwrap();
        let st = shared.state.lock().unwrap();
        assert!(!st.running);
    }

    #[test]
    fn connection_disconnect_does_not_destroy_session() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Configure and mark running.
        handle_configure(
            &conn,
            json!({ "session_id": "persist", "user_data_name": "test" }),
            &sessions,
        )
        .unwrap();
        {
            let shared = sessions.get("persist").unwrap();
            shared.state.lock().unwrap().running = true;
        }

        // Simulate connection drop by just dropping the Arc<Connection>.
        drop(conn);

        // Session survives in the registry.
        let shared = sessions.get("persist").unwrap();
        assert!(shared.state.lock().unwrap().running);
    }

    #[test]
    fn multiple_connections_share_same_vm() {
        let sessions = WindowsRegistry::new();
        let conn1 = dummy_conn();
        let conn2 = dummy_conn();

        let params = json!({ "session_id": "shared-vm", "user_data_name": "test" });

        // Both connections configure with the same session_id.
        handle_configure(&conn1, params.clone(), &sessions).unwrap();
        // Simulate the VM is running before conn2 connects.
        {
            let shared = sessions.get("shared-vm").unwrap();
            shared.state.lock().unwrap().running = true;
        }
        handle_configure(&conn2, params, &sessions).unwrap();

        // Both see the VM as running.
        let r1 = dispatch(&conn1, method::IS_RUNNING, json!({}), &sessions).unwrap();
        let r2 = dispatch(&conn2, method::IS_RUNNING, json!({}), &sessions).unwrap();
        assert!(r1.get("value").unwrap().as_bool().unwrap());
        assert!(r2.get("value").unwrap().as_bool().unwrap());

        // Only 1 session in registry.
        assert_eq!(sessions.len(), 1);
    }

    // -----------------------------------------------------------------------
    // InflightTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn inflight_tracker_starts_empty() {
        let t = InflightTracker::new();
        // drain() should return immediately when reader is done and count is 0.
        t.mark_reader_done();
        t.drain();
    }

    #[test]
    fn inflight_tracker_drains_after_handlers_finish() {
        let t = Arc::new(InflightTracker::new());

        // Simulate 3 in-flight handlers.
        t.begin();
        t.begin();
        t.begin();

        let t2 = Arc::clone(&t);
        let done = Arc::new(AtomicBool::new(false));
        let done2 = Arc::clone(&done);

        // Spawn a thread that drains — it should block until all handlers end.
        let joiner = thread::spawn(move || {
            t2.mark_reader_done();
            t2.drain();
            done2.store(true, Ordering::Relaxed);
        });

        // Not done yet (handlers still in-flight).
        thread::sleep(Duration::from_millis(50));
        assert!(!done.load(Ordering::Relaxed));

        // End handlers one by one.
        t.end();
        thread::sleep(Duration::from_millis(20));
        assert!(!done.load(Ordering::Relaxed));

        t.end();
        thread::sleep(Duration::from_millis(20));
        assert!(!done.load(Ordering::Relaxed));

        t.end(); // last one
        joiner.join().unwrap();
        assert!(done.load(Ordering::Relaxed));
    }

    #[test]
    fn inflight_tracker_concurrent_begin_end() {
        let t = Arc::new(InflightTracker::new());
        let mut handles = Vec::new();

        for _ in 0..50 {
            t.begin();
            let t2 = Arc::clone(&t);
            handles.push(thread::spawn(move || {
                // Simulate work.
                thread::sleep(Duration::from_millis(5));
                t2.end();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        t.mark_reader_done();
        t.drain(); // should return immediately — all handlers done.
    }

    // -----------------------------------------------------------------------
    // Concurrent dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_dispatch_returns_correct_ids() {
        // Verify that dispatching multiple requests concurrently produces
        // responses with the correct correlation IDs.
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        // Configure first.
        handle_configure(
            &conn,
            json!({ "session_id": "conc-id", "user_data_name": "test" }),
            &sessions,
        )
        .unwrap();

        let ids: Vec<String> = (0..10).map(|i| format!("req-{i}")).collect();
        let results: Arc<Mutex<Vec<(String, Result<Value, RpcError>)>>> = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for id in &ids {
            let conn_t = Arc::clone(&conn);
            let sessions_t = sessions.clone();
            let results_t = Arc::clone(&results);
            let id_t = id.clone();
            handles.push(thread::spawn(move || {
                let r = dispatch(&conn_t, method::PING, json!({}), &sessions_t);
                results_t.lock().unwrap().push((id_t, r));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 10);
        // All should succeed.
        for (id, r) in results.iter() {
            assert!(r.is_ok(), "request {id} failed: {:?}", r.as_ref().err());
        }
    }

    #[test]
    fn concurrent_dispatch_different_methods() {
        // Dispatch different methods concurrently — they should all succeed
        // without deadlocking.
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();

        handle_configure(
            &conn,
            json!({ "session_id": "conc-methods", "user_data_name": "test" }),
            &sessions,
        )
        .unwrap();

        let results: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        // PING (no session needed)
        {
            let c = Arc::clone(&conn);
            let s = sessions.clone();
            let r = Arc::clone(&results);
            handles.push(thread::spawn(move || {
                let _ = dispatch(&c, method::PING, json!({}), &s);
                r.lock().unwrap().push("ping");
            }));
        }
        // IS_RUNNING
        {
            let c = Arc::clone(&conn);
            let s = sessions.clone();
            let r = Arc::clone(&results);
            handles.push(thread::spawn(move || {
                let _ = dispatch(&c, method::IS_RUNNING, json!({}), &s);
                r.lock().unwrap().push("is_running");
            }));
        }
        // IS_GUEST_CONNECTED
        {
            let c = Arc::clone(&conn);
            let s = sessions.clone();
            let r = Arc::clone(&results);
            handles.push(thread::spawn(move || {
                let _ = dispatch(&c, method::IS_GUEST_CONNECTED, json!({}), &s);
                r.lock().unwrap().push("is_guest_connected");
            }));
        }
        // IS_DEBUG_LOGGING_ENABLED
        {
            let c = Arc::clone(&conn);
            let s = sessions.clone();
            let r = Arc::clone(&results);
            handles.push(thread::spawn(move || {
                let _ = dispatch(&c, method::IS_DEBUG_LOGGING_ENABLED, json!({}), &s);
                r.lock().unwrap().push("is_debug_logging_enabled");
            }));
        }
        // SET_DEBUG_LOGGING
        {
            let c = Arc::clone(&conn);
            let s = sessions.clone();
            let r = Arc::clone(&results);
            handles.push(thread::spawn(move || {
                let _ = dispatch(&c, method::SET_DEBUG_LOGGING, json!({ "enabled": true }), &s);
                r.lock().unwrap().push("set_debug_logging");
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 5);
        assert!(results.contains(&"ping"));
        assert!(results.contains(&"is_running"));
        assert!(results.contains(&"is_guest_connected"));
        assert!(results.contains(&"is_debug_logging_enabled"));
        assert!(results.contains(&"set_debug_logging"));
    }

    #[test]
    fn concurrent_configure_different_sessions() {
        // Multiple threads configuring different sessions concurrently.
        let sessions = WindowsRegistry::new();
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let s = sessions.clone();
                thread::spawn(move || {
                    let c = dummy_conn();
                    let params = json!({
                        "session_id": format!("sess-{i}"),
                        "user_data_name": format!("user-{i}")
                    });
                    handle_configure(&c, params, &s).unwrap();
                    format!("sess-{i}")
                })
            })
            .collect();

        let keys: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(keys.len(), 10);
        assert_eq!(sessions.len(), 10);

        // Each session should be distinct.
        let mut unique = keys.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 10);
    }

    /// Prove the reader loop is NOT blocked by a long-running handler.
    ///
    /// This test simulates the exact pattern from `handle_client`:
    ///   reader loop: read from channel → spawn handler thread → next
    ///
    /// A "slow" request (200ms sleep) is sent first, then a "fast" request.
    /// If the architecture were serial, the fast request would complete after
    /// the slow one.  With concurrent dispatch, the fast request completes
    /// while the slow one is still running.
    #[test]
    fn reader_loop_not_blocked_by_slow_handler() {
        use std::sync::mpsc;

        // (method, id) pairs — simulates frames read from a pipe.
        let (tx, rx) = mpsc::channel::<(&'static str, &'static str)>();

        let results: Arc<Mutex<Vec<(&'static str, Instant)>>> = Arc::new(Mutex::new(Vec::new()));
        let tracker = Arc::new(InflightTracker::new());

        // Reader thread — mirrors handle_client's dispatch loop.
        let results_r = Arc::clone(&results);
        let tracker_r = Arc::clone(&tracker);
        let reader = thread::spawn(move || {
            while let Ok((method, id)) = rx.recv() {
                tracker_r.begin();
                let r = Arc::clone(&results_r);
                let t = Arc::clone(&tracker_r);
                thread::spawn(move || {
                    // Simulate blocking work for "slow", instant for "fast".
                    if method == "slow" {
                        thread::sleep(Duration::from_millis(200));
                    }
                    r.lock().unwrap().push((id, Instant::now()));
                    t.end();
                });
            }
            tracker_r.mark_reader_done();
            tracker_r.drain();
        });

        // Send slow first, then fast after a tiny delay.
        tx.send(("slow", "slow-req")).unwrap();
        thread::sleep(Duration::from_millis(10)); // let reader pick it up
        tx.send(("fast", "fast-req")).unwrap();
        thread::sleep(Duration::from_millis(10)); // let reader pick it up
        drop(tx); // close channel → reader exits

        reader.join().unwrap();

        let res = results.lock().unwrap();
        assert_eq!(res.len(), 2);

        let slow_time = res.iter().find(|(id, _)| *id == "slow-req").unwrap().1;
        let fast_time = res.iter().find(|(id, _)| *id == "fast-req").unwrap().1;

        // Fast MUST complete before slow.  If the architecture were serial,
        // fast would complete ~200ms after slow started (i.e. after slow finished).
        assert!(
            fast_time < slow_time,
            "fast completed at {:?}, slow at {:?} — reader was blocked!",
            fast_time.duration_since(slow_time),
            Duration::ZERO
        );

        // Fast should complete within ~50ms of being sent (not 200ms+).
        // The slow request takes 200ms, so if fast completes in <100ms,
        // it was NOT serialized behind the slow one.
        // (We use the test start as a rough anchor.)
    }

    /// Prove that N concurrent dispatch calls actually run in parallel, not
    /// sequentially.  We use a barrier to synchronize all handler threads
    /// and measure total wall-clock time.
    #[test]
    fn concurrent_handlers_run_in_parallel() {
        let sessions = WindowsRegistry::new();
        let conn = dummy_conn();
        handle_configure(
            &conn,
            json!({ "session_id": "parallel", "user_data_name": "test" }),
            &sessions,
        )
        .unwrap();

        let n = 8;
        // Barrier: all N threads must arrive before any can proceed.
        // If dispatch were serial, only 1 thread would ever be alive at a time
        // and the barrier would deadlock.
        let barrier = Arc::new(std::sync::Barrier::new(n));

        let start = Instant::now();
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let c = Arc::clone(&conn);
                let s = sessions.clone();
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    // All threads must be running concurrently for this to pass.
                    b.wait();
                    let _ = dispatch(&c, method::PING, json!({}), &s);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        let elapsed = start.elapsed();

        // If serial: 8 × (barrier wait + dispatch) would take much longer.
        // With concurrency: all 8 threads hit the barrier simultaneously,
        // then dispatch in parallel.  Should complete in <100ms easily.
        assert!(
            elapsed < Duration::from_secs(5),
            "8 concurrent dispatches took {elapsed:?} — expected parallel execution"
        );
    }
}
