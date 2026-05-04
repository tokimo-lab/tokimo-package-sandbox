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

use std::collections::HashSet;

use tokimo_package_sandbox::canonicalize_safe;
use tokimo_package_sandbox::session_registry::{SessionRegistry, SharedSession};
use tokimo_package_sandbox::svc_protocol::{
    AddMountParams, BoolValue, CreateDiskImageParams, Frame, IdParams, JobIdListResult, JobIdResult,
    ListSessionsResult, MAX_FRAME_BYTES, PROTOCOL_VERSION, RemoveMountParams, ResizeShellParams, RootfsSpec, RpcError,
    SessionInfoResult, SessionNameParams, SignalShellParams, SpawnShellParams, WriteStdinParams, encode_frame, method,
};
use tokimo_package_sandbox::vfs_host::FuseHost;
use tokimo_package_sandbox::vfs_impls::LocalDirVfs;
use tokimo_package_sandbox::{ConfigureParams, Mount, NetworkPolicy};

mod hcs;
mod hvsock;
mod netstack;
mod svclog;
mod vhdx_pool;
mod vmconfig;

use svclog::slog;

/// Convert an [`hvsock::HvSock`] to a [`tokio::net::TcpStream`].
///
/// HvSocket uses Winsock2 `SOCK_STREAM` sockets. Tokio's reactor on
/// Windows uses IOCP which works with any Winsock socket regardless of
/// address family. We set the socket to non-blocking via `ioctlsocket`,
/// wrap it as a `std::net::TcpStream`, and let tokio register it with
/// IOCP.
///
/// **Must be called from within a tokio runtime context** (e.g. inside
/// `block_on` or an async task) so that `from_std` can register with
/// the reactor.
fn hvsock_to_tokio_stream(sock: hvsock::HvSock) -> std::io::Result<tokio::net::TcpStream> {
    use std::os::windows::io::{FromRawSocket, RawSocket};
    use windows::Win32::Networking::WinSock::{FIONBIO, SOCKET, ioctlsocket};

    let raw = sock.raw_socket();
    // Prevent the HvSock Drop from closing the socket — ownership moves
    // to the TcpStream.
    std::mem::forget(sock);

    // Set non-blocking via Winsock ioctlsocket so tokio's reactor can
    // drive it via IOCP.
    let mut mode: u32 = 1; // non-blocking
    let rc = unsafe { ioctlsocket(SOCKET(raw), FIONBIO, &mut mode) };
    if rc != 0 {
        return Err(std::io::Error::other("ioctlsocket FIONBIO failed"));
    }

    let std_stream = unsafe { std::net::TcpStream::from_raw_socket(raw as RawSocket) };
    tokio::net::TcpStream::from_std(std_stream)
}

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
    svclog::init_log();
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
    slog!("[svc] listening on {PIPE_NAME} (v{VERSION})");
    if verify_caller_required() {
        slog!("[svc] caller signature verification: ENFORCED");
    } else {
        slog!("[svc] caller signature verification: log-only");
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
            slog!("[svc] CreateNamedPipeW failed: {:?}", unsafe { GetLastError() });
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }

        let connect_evt = match create_event() {
            Ok(h) => h,
            Err(e) => {
                slog!("[svc] CreateEventW failed: {e}");
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
    /// Set to `true` once the child's exit has been observed and the
    /// `EV_EXIT` event sent by the session dispatcher thread.
    finished: Arc<AtomicBool>,
}

/// Handle for the single per-session event-dispatch thread that drains
/// stdout / stderr / exit events for all children in the session.
struct DispatcherHandle {
    stop: Arc<AtomicBool>,
    /// Kept so the thread is detached (and its resources freed) when the
    /// session is torn down.  We never join inside `teardown_session`
    /// because the caller holds the session mutex and the dispatcher also
    /// acquires it; instead we rely on `stop` + a dead init to make the
    /// thread exit promptly on its own.
    _join: thread::JoinHandle<()>,
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
    /// Single dispatch thread consuming events for all children in this
    /// session (stdout / stderr / exit → `EV_*` frames on the pipe).
    dispatcher: Option<DispatcherHandle>,
    /// FUSE-over-vsock host serving all user mounts.
    fuse_host: Option<Arc<FuseHost>>,
    /// Vsock port the FUSE listener accepts connections on.
    fuse_port: u32,
    /// Map of mount name → FUSE mount_id for currently registered mounts.
    fuse_mount_names: HashMap<String, u32>,
    /// Names of mounts declared at boot time (immutable; cannot be removed).
    boot_mount_names: HashSet<String>,
    /// Dedicated tokio runtime driving FuseHost serve tasks.
    fuse_rt: Option<tokio::runtime::Runtime>,
    /// Userspace netstack handle (None when NetworkPolicy::Blocked). The
    /// AtomicBool is the shutdown flag; setting it makes the netstack
    /// thread stop within ~50ms. The thread itself is detached.
    netstack_shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    running: bool,
    guest_connected: bool,
    /// Unix-millisecond timestamp captured when `running` flips to true.
    started_at_unix_ms: Option<u64>,
    /// Owner process ID for the connection that originally configured /
    /// started this session (best-effort; updated on each `configure`).
    /// Used by management RPCs and the owner-PID waiter.
    owner_pid: Option<u32>,
}

#[allow(clippy::derivable_impls)]
impl Default for SessionState {
    fn default() -> Self {
        Self {
            config: None,
            hcs: None,
            init: None,
            vhdx: None,
            shell_child_id: None,
            children: HashMap::new(),
            dispatcher: None,
            fuse_host: None,
            fuse_port: 0,
            fuse_mount_names: HashMap::new(),
            boot_mount_names: HashSet::new(),
            fuse_rt: None,
            netstack_shutdown: None,
            running: false,
            guest_connected: false,
            started_at_unix_ms: None,
            owner_pid: None,
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
    /// PID of the named-pipe peer (best-effort, captured at connect time
    /// via `GetNamedPipeClientProcessId`). Used by management RPCs and
    /// the owner-PID waiter to associate a session with a live caller.
    owner_pid: Option<u32>,
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
fn get_session(conn: &Connection, sessions: &WindowsRegistry) -> Result<Arc<SharedSession<SessionState>>, RpcError> {
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
        Some(p) => slog!("[svc] client connected: {}", p.display()),
        None => slog!("[svc] client connected: <unknown caller>"),
    }

    if verify_caller_required() {
        match caller.as_deref().and_then(safe_canon_or_log) {
            Some(canon) => {
                if let Err(why) = verify_authenticode(&canon) {
                    slog!("[svc] REJECT unsigned/untrusted caller {}: {why}", canon.display());
                    disconnect(pipe);
                    return;
                }
            }
            None => {
                slog!("[svc] REJECT caller: could not resolve image path");
                disconnect(pipe);
                return;
            }
        }
    }

    let conn = Arc::new(Connection {
        pipe,
        write_lock: Mutex::new(()),
        session_id: Mutex::new(None),
        owner_pid: caller_pid(pipe),
    });

    // Owner-PID waiter — auto-tear-down on caller exit.
    //
    // Why: the named-pipe transport doesn't surface "client process
    // crashed". If rust-server panics (or is killed mid-rebuild during
    // dev) while a Hyper-V VM is running, the svc has no way to know
    // the owner is gone — the VM keeps holding ~8 GiB of RAM until the
    // service is restarted. We block that leak by parking a thread on
    // `WaitForSingleObject(owner_proc, INFINITE)`; when it returns we
    // tear down the bound session if any.
    if let Some(pid) = conn.owner_pid {
        let sessions_w = sessions.clone();
        let conn_w = Arc::clone(&conn);
        std::thread::spawn(move || owner_pid_waiter(pid, conn_w, sessions_w));
    }
    // Hello handshake.
    match read_frame(pipe) {
        Ok(Frame::Hello { version, peer, .. }) => {
            slog!("[svc] hello from {peer} (proto v{version})");
            if version != PROTOCOL_VERSION {
                slog!("[svc] protocol version mismatch: client={version}, svc={PROTOCOL_VERSION}");
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
            slog!("[svc] expected Hello, got {other:?}");
            disconnect(pipe);
            return;
        }
        Err(e) => {
            slog!("[svc] failed to read Hello: {e}");
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
                    slog!("[svc] connection closed: {e}");
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
                        slog!("[svc] write response failed: {e}");
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

        method::ADD_MOUNT => {
            let p: AddMountParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_add_mount(conn, p, sessions)
        }
        method::REMOVE_MOUNT => {
            let p: RemoveMountParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_remove_mount(conn, p, sessions)
        }

        method::LIST_SESSIONS => handle_list_sessions(sessions),
        method::SESSION_INFO => {
            let p: SessionNameParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_session_info(sessions, p)
        }
        method::STOP_SESSION => {
            let p: SessionNameParams =
                serde_json::from_value(params).map_err(|e| RpcError::new("bad_params", e.to_string()))?;
            handle_stop_session(conn, sessions, p)
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
        let mut st = shared.state.lock().unwrap();
        if st.running {
            slog!("[svc] reusing existing session {key}");
            // Refresh owner_pid for the rebind so management RPCs and
            // the owner-PID waiter associate the live caller with the
            // session.
            if conn.owner_pid.is_some() {
                st.owner_pid = conn.owner_pid;
            }
            *conn.session_id.lock().unwrap() = Some(key);
            return Ok(json!({}));
        }
    }

    // Not running — store config.
    {
        let mut st = shared.state.lock().unwrap();
        st.config = Some(cfg);
        st.owner_pid = conn.owner_pid;
    }

    // Bind this connection to the session.
    *conn.session_id.lock().unwrap() = Some(key);
    Ok(json!({}))
}

fn handle_list_sessions(sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let mut out = Vec::new();
    for (name, shared) in sessions.entries() {
        let st = shared.state.lock().unwrap();
        out.push(summarize_session(&name, &st));
    }
    serde_json::to_value(ListSessionsResult { sessions: out }).map_err(|e| RpcError::new("encode", e.to_string()))
}

fn handle_session_info(sessions: &WindowsRegistry, p: SessionNameParams) -> Result<Value, RpcError> {
    let details = match sessions.get(&p.name) {
        None => None,
        Some(shared) => {
            let st = shared.state.lock().unwrap();
            Some(tokimo_package_sandbox::SessionDetails {
                summary: summarize_session(&p.name, &st),
                owner_pid: st.owner_pid,
                shell_count: st.children.len(),
                mount_count: st.fuse_mount_names.len(),
            })
        }
    };
    serde_json::to_value(SessionInfoResult { details }).map_err(|e| RpcError::new("encode", e.to_string()))
}

fn handle_stop_session(
    _conn: &Arc<Connection>,
    sessions: &WindowsRegistry,
    p: SessionNameParams,
) -> Result<Value, RpcError> {
    let Some(shared) = sessions.get(&p.name) else {
        // Idempotent — unknown session is a no-op.
        return Ok(json!({}));
    };
    // Owner-still-alive warning: the owner process for this session is
    // tracked in `SessionState.owner_pid`. We log when we're killing a
    // session whose owner is still running so this admin override is
    // visible in svc logs.
    let owner_alive = {
        let st = shared.state.lock().unwrap();
        st.owner_pid.map(is_pid_alive).unwrap_or(false)
    };
    if owner_alive {
        slog!(
            "[svc] stop_session: forcibly stopping session {} whose owner pid is still alive",
            p.name
        );
    }
    {
        let mut st = shared.state.lock().unwrap();
        teardown_session(&mut st);
    }
    sessions.remove(&p.name);
    Ok(json!({}))
}

/// Best-effort check whether `pid` still refers to a running process on
/// this host. Used by `stop_session` to log an admin-override warning.
fn is_pid_alive(pid: u32) -> bool {
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    let Ok(h) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return false;
    };
    // OpenProcess succeeds for both running and recently-exited processes
    // (until the handle table is reaped), but for our log-only purpose
    // this is good enough.
    let _ = unsafe { CloseHandle(h) };
    true
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
            // Idempotent: a second handle that joined this session via
            // configure() may legitimately call start_vm again. The VM
            // is already up, the boot shell already exists. Match the
            // SharedBackend (Linux/macOS) semantics — see
            // `tests::shared_session_two_handles_see_same_shell`.
            return Ok(json!({}));
        }
        st.config
            .clone()
            .ok_or_else(|| RpcError::new("not_configured", "configure() not called"))?
    };

    // Userspace netstack is always-on: even under NetworkPolicy::Blocked
    // the guest connects to the smoltcp gateway and `EgressPolicy` inside
    // the gateway drops upstream traffic. This unifies the L4 audit path
    // across all 3 backends and lets us route in-process LocalService
    // entries (e.g. NFS) regardless of policy.
    let netstack_port: Option<u32> = Some(vmconfig::alloc_session_init_port());

    let (kernel, initrd, rootfs_template) = resolve_vm_artifacts(&cfg).map_err(|e| RpcError::new("bad_path", e))?;

    if cfg.mounts.is_empty() {
        return Err(RpcError::new("validation", "at least one mount is required on Windows"));
    }
    if cfg.mounts.len() > 64 {
        return Err(RpcError::new(
            "validation",
            format!("too many mounts: {} (max 64)", cfg.mounts.len()),
        ));
    }

    // Canonicalise share host paths (TOCTOU-safe).
    let mut canon_shares: Vec<(PathBuf, &tokimo_package_sandbox::Mount)> = Vec::new();
    for (i, s) in cfg.mounts.iter().enumerate() {
        let canon = canonicalize_safe(&s.host_path).map_err(|e| {
            RpcError::new(
                "bad_path",
                format!("mounts[{i}].host_path ({}): {e}", s.host_path.display()),
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

    // Per-session netstack hvsock listener. Always created (see
    // netstack_port comment above). Must be bound BEFORE HCS starts so
    // the guest can connect immediately at boot.
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

    let fuse_port = vmconfig::alloc_fuse_port();

    let cfg_json = vmconfig::build_session_v2_ex(
        &vm_id,
        &kernel,
        &initrd,
        lease.path(),
        cfg.memory_mb,
        cfg.cpu_count as usize,
        init_port,
        fuse_port,
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

    // Accept the netstack connection. Always present now — the guest's
    // `tokimo-tun-pump` connects from inside the VM after init.sh brings
    // up tk0. We accept AFTER init.hello() so a slow netstack accept
    // doesn't block the init handshake; the pump retries connect for ~30s.
    let netstack_shutdown = if let Some(listener) = netstack_listener {
        match hvsock::accept_guest(&listener, Duration::from_secs(30)) {
            Ok(net_sock) => {
                drop(listener);
                match net_sock.try_clone() {
                    Ok(writer) => {
                        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let policy = match cfg.network {
                            NetworkPolicy::AllowAll => netstack::EgressPolicy::AllowAll,
                            NetworkPolicy::Blocked => netstack::EgressPolicy::Blocked,
                        };
                        let _ = netstack::spawn(
                            Box::new(net_sock),
                            Box::new(writer),
                            Arc::clone(&shutdown),
                            policy,
                            Vec::new(),
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

    // Set up FUSE-over-vsock host for user mounts.
    let fuse_host: Arc<FuseHost> = Arc::new(FuseHost::new());
    let fuse_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| RpcError::new("tokio_rt", e.to_string()))?;

    // Spawn an HvSocket accept loop for FUSE connections in a
    // background thread. Each accepted connection gets its own
    // dedicated tokio runtime (single-threaded) so that
    // TcpStream::from_std has a reactor available.
    {
        let fuse_host = fuse_host.clone();
        thread::spawn(move || {
            loop {
                match hvsock::listen_and_accept_on_port(fuse_port) {
                    Ok(hv) => {
                        let host = fuse_host.clone();
                        thread::spawn(move || {
                            // Create a dedicated single-threaded tokio
                            // runtime for this connection. This ensures
                            // from_std() has a reactor available.
                            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                                Ok(rt) => rt,
                                Err(e) => {
                                    eprintln!("[fuse] runtime build: {e}");
                                    return;
                                }
                            };
                            rt.block_on(async move {
                                let stream = match hvsock_to_tokio_stream(hv) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        eprintln!("[fuse] hvsock_to_tokio: {e}");
                                        return;
                                    }
                                };
                                if let Err(e) = host.serve(stream).await {
                                    eprintln!("[fuse] serve: {e}");
                                }
                            });
                        });
                    }
                    Err(e) => {
                        eprintln!("[fuse] accept error: {e}");
                        break;
                    }
                }
            }
        });
    }

    // Register boot-time mounts with FuseHost and tell the guest to
    // mount them via FUSE.
    let mut fuse_mount_names = HashMap::new();
    let mut boot_mount_names = HashSet::new();
    for (canon_path, spec) in canon_shares.iter() {
        let backend = LocalDirVfs::arc(canon_path.clone());
        let mount_id = fuse_host.register_mount(&spec.name, backend, spec.read_only);
        if let Err(e) = init.mount_fuse(
            &spec.name,
            fuse_port,
            &spec.guest_path.to_string_lossy(),
            spec.read_only,
        ) {
            fuse_host.remove_mount(mount_id);
            return Err(RpcError::new("mount_fuse", e.to_string()));
        }
        fuse_mount_names.insert(spec.name.clone(), mount_id);
        boot_mount_names.insert(spec.name.clone());
    }

    // Auto-start a shell inside the VM.
    let shell_info = init
        .open_shell(&["/bin/bash"], &[], None)
        .map_err(|e| RpcError::new("open_shell", e.to_string()))?;
    let shell_child_id = shell_info.child_id;

    // Install state.
    let init_arc = Arc::new(init);

    {
        let mut st = shared.state.lock().unwrap();
        st.hcs = Some((api.clone(), cs, vm_id.clone()));
        st.init = Some(Arc::clone(&init_arc));
        st.vhdx = Some(lease);
        st.shell_child_id = Some(shell_child_id.clone());
        st.children.insert(
            shell_child_id,
            ChildEntry {
                finished: Arc::new(AtomicBool::new(false)),
            },
        );
        st.netstack_shutdown = netstack_shutdown;
        st.running = true;
        st.guest_connected = true;
        st.started_at_unix_ms = Some(svc_now_unix_ms());
        st.fuse_host = Some(fuse_host);
        st.fuse_port = fuse_port;
        st.fuse_mount_names = fuse_mount_names;
        st.boot_mount_names = boot_mount_names;
        st.fuse_rt = Some(fuse_rt);
    }

    // Spawn the single per-session dispatcher thread AFTER releasing the
    // session lock so the thread can acquire it on its first iteration
    // without risk of deadlock.
    {
        let disp_stop = Arc::new(AtomicBool::new(false));
        let disp_join = {
            let conn_w = Arc::clone(conn);
            let init_w = Arc::clone(&init_arc);
            let shared_w = Arc::clone(&shared);
            let stop_w = Arc::clone(&disp_stop);
            thread::spawn(move || dispatcher_loop(conn_w, init_w, shared_w, stop_w))
        };
        let mut st = shared.state.lock().unwrap();
        st.dispatcher = Some(DispatcherHandle {
            stop: disp_stop,
            _join: disp_join,
        });
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
    // Signal the dispatcher to stop.  We do not join here because the
    // caller holds the session mutex and the dispatcher also acquires it;
    // setting `stop` (plus the init EOF below) makes the thread exit
    // within one loop iteration without needing a join.
    if let Some(ref d) = st.dispatcher {
        d.stop.store(true, Ordering::Relaxed);
    }
    if let Some(init) = st.init.take() {
        let _ = init.shutdown();
    }
    if let Some((api, cs, _vm_id)) = st.hcs.take() {
        let _ = api.terminate_compute_system(cs);
        api.close_compute_system(cs);
    }
    st.shell_child_id = None;
    st.children.clear();
    // Detach the dispatcher JoinHandle; the thread exits promptly because
    // we set `stop` above and the init is now dead.
    st.dispatcher = None;
    // Drop FuseHost first (causes in-flight serve tasks to see EOF),
    // then shut down the tokio runtime.
    st.fuse_host = None;
    if let Some(rt) = st.fuse_rt.take() {
        drop(rt);
    }
    st.fuse_mount_names.clear();
    st.boot_mount_names.clear();
    st.vhdx = None;
    // Stop the userspace netstack thread before tearing down HCS so it
    // can flush in-flight frames cleanly.
    if let Some(s) = st.netstack_shutdown.take() {
        s.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    st.running = false;
    st.guest_connected = false;
    st.started_at_unix_ms = None;
}

fn svc_now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn summarize_session(name: &str, st: &SessionState) -> tokimo_package_sandbox::SessionSummary {
    tokimo_package_sandbox::SessionSummary {
        name: name.to_string(),
        user_data_name: st.config.as_ref().map(|c| c.user_data_name.clone()).unwrap_or_default(),
        running: st.running,
        guest_connected: st.guest_connected,
        memory_mb: st.config.as_ref().map(|c| c.memory_mb).unwrap_or(0),
        started_at_unix_ms: st.started_at_unix_ms,
    }
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
        (Some(rows), Some(cols)) => {
            let (info, _) = init
                .spawn_pty(&argv, &env, cwd.as_deref(), rows, cols)
                .map_err(|e| RpcError::new("spawn_pty", e.to_string()))?;
            info
        }
        _ => init
            .spawn_pipes(&argv, &env, cwd.as_deref())
            .map_err(|e| RpcError::new("spawn_pipes", e.to_string()))?,
    };
    let child_id = shell_info.child_id;

    {
        let shared = get_session(conn, sessions)?;
        let mut st = shared.state.lock().unwrap();
        st.children.insert(
            child_id.clone(),
            ChildEntry {
                finished: Arc::new(AtomicBool::new(false)),
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

/// Single per-session dispatch thread: waits for any child event, drains all
/// pending stdout / stderr / exit events, and forwards them as `EV_*` frames
/// on the pipe.  Replaces the previous N-thread model (one per child).
fn dispatcher_loop(
    conn: Arc<Connection>,
    init: Arc<tokimo_package_sandbox::init_client::WinInitClient>,
    shared: Arc<tokimo_package_sandbox::session_registry::SharedSession<SessionState>>,
    stop: Arc<AtomicBool>,
) {
    use tokimo_package_sandbox::init_client::DrainedEvent;
    loop {
        if stop.load(Ordering::Relaxed) || init.is_dead() {
            return;
        }

        // Snapshot child IDs; release lock before blocking.
        let ids: HashSet<String> = {
            let st = shared.state.lock().unwrap();
            st.children.keys().cloned().collect()
        };

        if ids.is_empty() {
            // No children yet; yield and try again shortly.
            thread::sleep(Duration::from_millis(20));
            continue;
        }

        // Block until any child has data, the init died, or timeout.
        let _ = init.wait_any_event_or_eof(Instant::now() + Duration::from_millis(250));

        if stop.load(Ordering::Relaxed) || init.is_dead() {
            return;
        }

        let drained = init.drain_pending_events_for(&ids);
        if drained.is_empty() {
            continue;
        }

        let mut to_close: Vec<String> = Vec::new();
        for ev in drained {
            match ev {
                DrainedEvent::Stdout { child_id, data } => {
                    let _ = send_event(&conn, method::EV_STDOUT, json!({ "id": child_id, "data": data }));
                }
                DrainedEvent::Stderr { child_id, data } => {
                    let _ = send_event(&conn, method::EV_STDERR, json!({ "id": child_id, "data": data }));
                }
                DrainedEvent::Exit { child_id, code, signal } => {
                    let _ = send_event(
                        &conn,
                        method::EV_EXIT,
                        json!({ "id": child_id, "exit_code": code, "signal": signal }),
                    );
                    to_close.push(child_id);
                }
            }
        }

        for cid in to_close {
            let _ = init.close_child(&cid);
            // Use try_lock so we never block the dispatcher on teardown.
            if let Ok(mut st) = shared.state.try_lock() {
                if let Some(entry) = st.children.get(&cid) {
                    entry.finished.store(true, Ordering::Relaxed);
                }
            }
        }
    }
}

fn handle_add_mount(conn: &Arc<Connection>, p: AddMountParams, sessions: &WindowsRegistry) -> Result<Value, RpcError> {
    let share: Mount = p.share;
    if share.name.is_empty() {
        return Err(RpcError::new("validation", "share name must not be empty"));
    }
    let shared = get_session(conn, sessions)?;
    let (fuse_host, fuse_port, init) = {
        let st = shared.state.lock().unwrap();
        if !st.running {
            return Err(RpcError::new(
                "vm_not_running",
                "VM is not running; call startVm() first",
            ));
        }
        if st.fuse_mount_names.contains_key(&share.name) {
            return Err(RpcError::new(
                "duplicate_share",
                format!("share {:?} already attached", share.name),
            ));
        }
        let fuse_host = st
            .fuse_host
            .clone()
            .ok_or_else(|| RpcError::new("vm_not_running", "no FuseHost"))?;
        let init = st
            .init
            .clone()
            .ok_or_else(|| RpcError::new("vm_not_running", "no init client"))?;
        (fuse_host, st.fuse_port, init)
    };

    let canon = canonicalize_safe(&share.host_path)
        .map_err(|e| RpcError::new("bad_path", format!("host_path ({}): {e}", share.host_path.display())))?;

    let backend = LocalDirVfs::arc(canon);
    let mount_id = fuse_host.register_mount(&share.name, backend, share.read_only);
    if let Err(e) = init.mount_fuse(
        &share.name,
        fuse_port,
        &share.guest_path.to_string_lossy(),
        share.read_only,
    ) {
        fuse_host.remove_mount(mount_id);
        return Err(RpcError::new("guest_mount", e.to_string()));
    }

    {
        let mut st = shared.state.lock().unwrap();
        st.fuse_mount_names.insert(share.name.clone(), mount_id);
    }

    Ok(json!({}))
}

fn handle_remove_mount(
    conn: &Arc<Connection>,
    p: RemoveMountParams,
    sessions: &WindowsRegistry,
) -> Result<Value, RpcError> {
    let name = p.name;
    if name.is_empty() {
        return Err(RpcError::new("validation", "share name must not be empty"));
    }

    let shared = get_session(conn, sessions)?;
    let (fuse_host, init) = {
        let st = shared.state.lock().unwrap();
        if !st.running {
            return Err(RpcError::new(
                "vm_not_running",
                "VM is not running; call startVm() first",
            ));
        }
        if st.boot_mount_names.contains(&name) {
            return Err(RpcError::new(
                "immutable_share",
                format!("share {name:?} was attached at boot and cannot be removed"),
            ));
        }
        if !st.fuse_mount_names.contains_key(&name) {
            return Err(RpcError::new("unknown_share", format!("no share named {name:?}")));
        }
        let fuse_host = st
            .fuse_host
            .clone()
            .ok_or_else(|| RpcError::new("vm_not_running", "no FuseHost"))?;
        let init = st
            .init
            .clone()
            .ok_or_else(|| RpcError::new("vm_not_running", "no init client"))?;
        (fuse_host, init)
    };

    // Unmount guest-side first (umount + SIGTERM fuse child).
    if let Err(e) = init.unmount_fuse(&name) {
        return Err(RpcError::new("guest_unmount", e.to_string()));
    }

    // Deregister the backend from FuseHost.
    if let Some(mount_id) = fuse_host.mount_id_by_name(&name) {
        fuse_host.remove_mount(mount_id);
    }

    {
        let mut st = shared.state.lock().unwrap();
        st.fuse_mount_names.remove(&name);
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
    Err(format!(
        "could not locate vm/{name}. Place vmlinuz + initrd.img + rootfs.vhdx in <repo>/vm/. Run scripts/windows/fetch-vm.ps1 to download."
    ))
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
            slog!("[svc] path rejected ({}): {e}", p.display());
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
    let pid = caller_pid(pipe)?;
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

/// Returns the named-pipe peer PID, or `None` if unavailable.
fn caller_pid(pipe: HANDLE) -> Option<u32> {
    let mut pid: u32 = 0;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid).ok()? };
    Some(pid)
}

/// Block on the owner process handle; on its exit, tear down whichever
/// session this connection happens to be bound to at that moment.
///
/// Notes:
/// * `OpenProcess(SYNCHRONIZE)` requires the same SID or admin
///   privileges. The svc always runs as LocalSystem, so this never
///   fails for production callers.
/// * The connection's `session_id` may legitimately be `None` (caller
///   died before configuring) or point to a session that has already
///   been torn down (caller died after `stop_vm`). Both are no-ops.
/// * Re-entrancy: if the same caller crashes twice in quick succession
///   it'll spawn two waiters; that's fine, the second one finds no
///   session and does nothing.
fn owner_pid_waiter(pid: u32, conn: Arc<Connection>, sessions: WindowsRegistry) {
    // SYNCHRONIZE = 0x00100000 (standard right). Not exposed by name
    // on `PROCESS_ACCESS_RIGHTS` in windows-rs but is a valid value.
    let access = windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(0x0010_0000);
    let proc_h = match unsafe { OpenProcess(access, false, pid) } {
        Ok(h) => h,
        Err(e) => {
            slog!("[svc] owner-waiter: OpenProcess({pid}) failed: {e}");
            return;
        }
    };

    unsafe { WaitForSingleObject(proc_h, u32::MAX) };
    let _ = unsafe { CloseHandle(proc_h) };

    let bound = conn.session_id.lock().unwrap().clone();
    let Some(key) = bound else {
        slog!("[svc] owner-waiter: pid {pid} exited; no session bound — nothing to do");
        return;
    };
    let Some(shared) = sessions.get(&key) else {
        slog!("[svc] owner-waiter: pid {pid} exited; session {key} already gone");
        return;
    };
    slog!("[svc] owner-waiter: pid {pid} exited; tearing down session {key}");
    {
        let mut st = shared.state.lock().unwrap();
        teardown_session(&mut st);
    }
    sessions.remove(&key);
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
            owner_pid: None,
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
        assert!(st.fuse_mount_names.is_empty());
        assert!(st.boot_mount_names.is_empty());
    }

    #[test]
    fn session_state_trait_impl() {
        let mut st = SessionState {
            running: true,
            ..Default::default()
        };
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
        #[allow(clippy::type_complexity)]
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
