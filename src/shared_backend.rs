//! Process-wide session sharing for in-process backends (Linux / macOS).
//!
//! ## Why
//!
//! On Windows the VM lives inside `tokimo-sandbox-svc.exe` (LocalSystem)
//! and the library is just a named-pipe client.  Two `Sandbox::connect()`
//! calls that supply the same `session_id` end up driving the **same**
//! VM, because the service deduplicates by id (see
//! [`SessionRegistry`](crate::session_registry::SessionRegistry) used in
//! `src/bin/tokimo-sandbox-svc/`).
//!
//! Linux and macOS used to run the entire backend inside the user
//! process, with one VM per `Sandbox` handle and no sharing.  This module
//! restores Windows-equivalent **API semantics** by interposing a
//! process-wide registry between [`Sandbox`](crate::Sandbox) and the
//! per-platform backend (`MacosBackend` / `LinuxBackend`):
//!
//! ```text
//! Sandbox::connect()  →  SharedBackend<B>  ─┐
//! Sandbox::connect()  →  SharedBackend<B>  ─┤  same session_id  →
//! Sandbox::connect()  →  SharedBackend<B>  ─┘    one shared B  ─→  one VM
//! ```
//!
//! Two handles configured with the same non-empty `session_id` resolve
//! to the same inner `Arc<B>`; the second `configure()` is a no-op when
//! the VM is already running, the second `start_vm()` is idempotent, and
//! `stop_vm()` from any handle tears down the shared VM for everyone.
//!
//! An empty `session_id` → fresh, **untracked** backend (one-shot,
//! never reachable by another `connect()`).
//!
//! ## Limitations vs the Windows model (intentional, see plan)
//!
//! | Capability                                | Windows | Shared (mac/linux) |
//! |-------------------------------------------|:-------:|:-------------------:|
//! | Multi-handle share inside one process     |   ✅    |          ✅         |
//! | Reconnect after **client process** death  |   ✅    |          ❌         |
//! | VM survives client crash                  |   ✅    |          ❌         |
//! | Cross-process session lookup              |   ✅    |          ❌         |
//!
//! Closing all handles without calling `stop_vm()` leaks the registry
//! entry until the process exits.  Future work: an out-of-process
//! launchd / systemd helper would close the gap, at the cost of code
//! signing & entitlement complexity (VZ on macOS, root on Linux).

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use crate::api::{AddUserOpts, ConfigureParams, Event, JobId, Mount, ShellOpts};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};

/// Shared, process-wide map of `session_id → Arc<B>`.
pub type Registry<B> = Mutex<HashMap<String, Arc<B>>>;

/// Wrapper that turns a per-platform in-process backend into one that
/// shares VM state by `session_id` within the host process.
pub struct SharedBackend<B: SandboxBackend> {
    registry: &'static Registry<B>,
    factory: fn() -> Result<Arc<B>>,
    /// Resolved on the first `configure()`; subsequent calls forward to
    /// this instance.  Reset to `None` on `stop_vm()` so a single handle
    /// can be re-configured for a brand new session.
    inner: Mutex<Option<Arc<B>>>,
    /// `session_id` this handle is bound to (for cleanup on stop).
    /// `None` for empty / untracked sessions.
    bound_session: Mutex<Option<String>>,
}

impl<B: SandboxBackend> SharedBackend<B> {
    pub fn new(registry: &'static Registry<B>, factory: fn() -> Result<Arc<B>>) -> Self {
        Self {
            registry,
            factory,
            inner: Mutex::new(None),
            bound_session: Mutex::new(None),
        }
    }

    /// Resolve (or create) the inner backend for a given `session_id`.
    ///
    /// * `session_id` empty → untracked, fresh backend each time.
    /// * `session_id` known → reuse the existing `Arc<B>`.
    /// * Otherwise         → create via the factory, insert into the
    ///   registry, return.
    fn resolve(&self, session_id: &str) -> Result<Arc<B>> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(b) = inner.as_ref() {
            return Ok(Arc::clone(b));
        }

        let backend = if session_id.is_empty() {
            (self.factory)()?
        } else {
            let mut reg = self.registry.lock().unwrap();
            if let Some(existing) = reg.get(session_id) {
                Arc::clone(existing)
            } else {
                let fresh = (self.factory)()?;
                reg.insert(session_id.to_string(), Arc::clone(&fresh));
                fresh
            }
        };

        *inner = Some(Arc::clone(&backend));
        *self.bound_session.lock().unwrap() = if session_id.is_empty() {
            None
        } else {
            Some(session_id.to_string())
        };
        Ok(backend)
    }

    fn get(&self) -> Result<Arc<B>> {
        self.inner.lock().unwrap().clone().ok_or(Error::NotConfigured)
    }

    /// Tear down this handle's binding without touching VM state.  Used
    /// after `stop_vm()` so subsequent `configure()` on the same handle
    /// produces a clean, fresh session.
    fn drop_binding(&self) {
        if let Some(sid) = self.bound_session.lock().unwrap().take() {
            self.registry.lock().unwrap().remove(&sid);
        }
        *self.inner.lock().unwrap() = None;
    }

    /// Number of sessions currently tracked in this registry.  Test-only.
    #[cfg(test)]
    pub fn registry_len(registry: &'static Registry<B>) -> usize {
        registry.lock().unwrap().len()
    }
}

impl<B: SandboxBackend> SandboxBackend for SharedBackend<B> {
    fn configure(&self, params: ConfigureParams) -> Result<()> {
        let inner = self.resolve(&params.session_id)?;
        // Idempotent on a running shared session — matches Windows
        // service behaviour where the second `configure()` for an
        // already-running session_id returns immediately.
        if inner.is_running().unwrap_or(false) {
            return Ok(());
        }
        inner.configure(params)
    }

    fn create_vm(&self) -> Result<()> {
        self.get()?.create_vm()
    }

    fn start_vm(&self) -> Result<()> {
        let inner = self.get()?;
        if inner.is_running().unwrap_or(false) {
            return Ok(());
        }
        inner.start_vm()
    }

    fn stop_vm(&self) -> Result<()> {
        let inner = match self.get() {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        let result = inner.stop_vm();
        // Whether stop succeeded or not, drop the binding: the inner
        // backend's state machine no longer accepts further work, and
        // we don't want a half-dead Arc to be reused by a fresh
        // session_id lookup.
        self.drop_binding();
        result
    }

    fn is_running(&self) -> Result<bool> {
        match self.inner.lock().unwrap().clone() {
            Some(b) => b.is_running(),
            None => Ok(false),
        }
    }

    fn is_guest_connected(&self) -> Result<bool> {
        match self.inner.lock().unwrap().clone() {
            Some(b) => b.is_guest_connected(),
            None => Ok(false),
        }
    }

    fn is_process_running(&self, id: &JobId) -> Result<bool> {
        self.get()?.is_process_running(id)
    }

    fn shell_id(&self) -> Result<JobId> {
        self.get()?.shell_id()
    }

    fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId> {
        self.get()?.spawn_shell(opts)
    }

    fn resize_shell(&self, id: &JobId, rows: u16, cols: u16) -> Result<()> {
        self.get()?.resize_shell(id, rows, cols)
    }

    fn close_shell(&self, id: &JobId) -> Result<()> {
        self.get()?.close_shell(id)
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        self.get()?.list_shells()
    }

    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        self.get()?.write_stdin(id, data)
    }

    fn signal_shell(&self, id: &JobId, sig: i32) -> Result<()> {
        self.get()?.signal_shell(id, sig)
    }

    fn subscribe(&self) -> Result<Receiver<Event>> {
        self.get()?.subscribe()
    }

    fn create_disk_image(&self, path: &Path, gib: u64) -> Result<()> {
        self.get()?.create_disk_image(path, gib)
    }

    fn set_debug_logging(&self, enabled: bool) -> Result<()> {
        self.get()?.set_debug_logging(enabled)
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        self.get()?.is_debug_logging_enabled()
    }

    fn send_guest_response(&self, raw: serde_json::Value) -> Result<()> {
        self.get()?.send_guest_response(raw)
    }

    fn passthrough(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        self.get()?.passthrough(method, params)
    }

    fn add_mount(&self, share: Mount) -> Result<()> {
        self.get()?.add_mount(share)
    }

    fn remove_mount(&self, name: &str) -> Result<()> {
        self.get()?.remove_mount(name)
    }

    fn add_user(&self, user_id: &str, opts: AddUserOpts) -> Result<JobId> {
        self.get()?.add_user(user_id, opts)
    }

    fn remove_user(&self, user_id: &str) -> Result<()> {
        self.get()?.remove_user(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Minimal backend stub used to exercise SharedBackend logic without
    /// booting a real VM.
    struct FakeBackend {
        configured: AtomicBool,
        running: AtomicBool,
        stopped: AtomicBool,
        id: u32,
    }

    static FAKE_ID: AtomicU32 = AtomicU32::new(0);

    impl FakeBackend {
        fn new() -> Self {
            Self {
                configured: AtomicBool::new(false),
                running: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                id: FAKE_ID.fetch_add(1, Ordering::Relaxed),
            }
        }
    }

    impl SandboxBackend for FakeBackend {
        fn configure(&self, _p: ConfigureParams) -> Result<()> {
            self.configured.store(true, Ordering::Relaxed);
            Ok(())
        }
        fn create_vm(&self) -> Result<()> {
            Ok(())
        }
        fn start_vm(&self) -> Result<()> {
            self.running.store(true, Ordering::Relaxed);
            Ok(())
        }
        fn stop_vm(&self) -> Result<()> {
            self.running.store(false, Ordering::Relaxed);
            self.stopped.store(true, Ordering::Relaxed);
            Ok(())
        }
        fn is_running(&self) -> Result<bool> {
            Ok(self.running.load(Ordering::Relaxed))
        }
        fn is_guest_connected(&self) -> Result<bool> {
            self.is_running()
        }
        fn is_process_running(&self, _id: &JobId) -> Result<bool> {
            Ok(false)
        }
        fn shell_id(&self) -> Result<JobId> {
            Ok(JobId(format!("fake-{}", self.id)))
        }
        fn spawn_shell(&self, _o: ShellOpts) -> Result<JobId> {
            Err(Error::not_implemented("fake"))
        }
        fn resize_shell(&self, _i: &JobId, _r: u16, _c: u16) -> Result<()> {
            Ok(())
        }
        fn close_shell(&self, _i: &JobId) -> Result<()> {
            Ok(())
        }
        fn list_shells(&self) -> Result<Vec<JobId>> {
            Ok(vec![])
        }
        fn write_stdin(&self, _i: &JobId, _d: &[u8]) -> Result<()> {
            Ok(())
        }
        fn signal_shell(&self, _i: &JobId, _s: i32) -> Result<()> {
            Ok(())
        }
        fn subscribe(&self) -> Result<Receiver<Event>> {
            let (_tx, rx) = std::sync::mpsc::channel();
            Ok(rx)
        }
        fn create_disk_image(&self, _p: &Path, _g: u64) -> Result<()> {
            Ok(())
        }
        fn set_debug_logging(&self, _e: bool) -> Result<()> {
            Ok(())
        }
        fn is_debug_logging_enabled(&self) -> Result<bool> {
            Ok(false)
        }
        fn send_guest_response(&self, _r: serde_json::Value) -> Result<()> {
            Ok(())
        }
        fn passthrough(&self, _m: &str, _p: serde_json::Value) -> Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
        fn add_mount(&self, _s: Mount) -> Result<()> {
            Ok(())
        }
        fn remove_mount(&self, _n: &str) -> Result<()> {
            Ok(())
        }
        fn add_user(&self, _u: &str, _o: AddUserOpts) -> Result<JobId> {
            Err(Error::not_implemented("fake"))
        }
        fn remove_user(&self, _u: &str) -> Result<()> {
            Ok(())
        }
    }

    fn make_fake() -> Result<Arc<FakeBackend>> {
        Ok(Arc::new(FakeBackend::new()))
    }

    /// Per-test isolated registry — using OnceLock leaked into 'static.
    fn fresh_registry() -> &'static Registry<FakeBackend> {
        Box::leak(Box::new(Mutex::new(HashMap::new())))
    }

    fn cfg(session_id: &str) -> ConfigureParams {
        ConfigureParams {
            session_id: session_id.into(),
            ..Default::default()
        }
    }

    #[test]
    fn calls_before_configure_error() {
        let reg = fresh_registry();
        let sb = SharedBackend::new(reg, make_fake);
        assert!(matches!(sb.start_vm(), Err(Error::NotConfigured)));
        assert!(matches!(sb.shell_id(), Err(Error::NotConfigured)));
    }

    #[test]
    fn is_running_is_false_before_configure() {
        let reg = fresh_registry();
        let sb = SharedBackend::new(reg, make_fake);
        assert!(!sb.is_running().unwrap());
        assert!(!sb.is_guest_connected().unwrap());
    }

    #[test]
    fn same_session_id_shares_backend() {
        let reg = fresh_registry();
        let h1 = SharedBackend::new(reg, make_fake);
        let h2 = SharedBackend::new(reg, make_fake);

        h1.configure(cfg("S")).unwrap();
        h1.start_vm().unwrap();

        h2.configure(cfg("S")).unwrap();
        // Second handle observes the running VM.
        assert!(h2.is_running().unwrap());
        // Same shell_id → same underlying backend instance.
        assert_eq!(h1.shell_id().unwrap(), h2.shell_id().unwrap());

        // Registry holds exactly one entry.
        assert_eq!(SharedBackend::<FakeBackend>::registry_len(reg), 1);
    }

    #[test]
    fn different_session_ids_isolate() {
        let reg = fresh_registry();
        let h1 = SharedBackend::new(reg, make_fake);
        let h2 = SharedBackend::new(reg, make_fake);

        h1.configure(cfg("A")).unwrap();
        h2.configure(cfg("B")).unwrap();
        assert_ne!(h1.shell_id().unwrap(), h2.shell_id().unwrap());
        assert_eq!(SharedBackend::<FakeBackend>::registry_len(reg), 2);
    }

    #[test]
    fn empty_session_id_is_untracked() {
        let reg = fresh_registry();
        let h1 = SharedBackend::new(reg, make_fake);
        let h2 = SharedBackend::new(reg, make_fake);

        h1.configure(cfg("")).unwrap();
        h2.configure(cfg("")).unwrap();
        // Two empty session_ids → two distinct fresh backends.
        assert_ne!(h1.shell_id().unwrap(), h2.shell_id().unwrap());
        assert_eq!(SharedBackend::<FakeBackend>::registry_len(reg), 0);
    }

    #[test]
    fn stop_vm_clears_registry_entry() {
        let reg = fresh_registry();
        let h1 = SharedBackend::new(reg, make_fake);

        h1.configure(cfg("X")).unwrap();
        h1.start_vm().unwrap();
        assert_eq!(SharedBackend::<FakeBackend>::registry_len(reg), 1);

        h1.stop_vm().unwrap();
        assert_eq!(SharedBackend::<FakeBackend>::registry_len(reg), 0);

        // After stop, this handle is "fresh": configure with a new
        // session_id installs a new entry.
        h1.configure(cfg("Y")).unwrap();
        assert_eq!(SharedBackend::<FakeBackend>::registry_len(reg), 1);
    }

    #[test]
    fn configure_on_running_session_is_idempotent() {
        let reg = fresh_registry();
        let h1 = SharedBackend::new(reg, make_fake);
        let h2 = SharedBackend::new(reg, make_fake);

        h1.configure(cfg("Z")).unwrap();
        h1.start_vm().unwrap();

        // h2.configure must not fail even though backend is Running.
        h2.configure(cfg("Z")).unwrap();
        // h2.start_vm must be idempotent too.
        h2.start_vm().unwrap();
        assert!(h2.is_running().unwrap());
    }

    #[test]
    fn stop_from_one_handle_tears_down_for_all() {
        let reg = fresh_registry();
        let h1 = SharedBackend::new(reg, make_fake);
        let h2 = SharedBackend::new(reg, make_fake);

        h1.configure(cfg("T")).unwrap();
        h1.start_vm().unwrap();
        h2.configure(cfg("T")).unwrap();
        assert!(h2.is_running().unwrap());

        h1.stop_vm().unwrap();

        // h2's bound inner backend reflects the shared stop.
        assert!(!h2.is_running().unwrap());
    }

    // OnceLock + leak warnings: silence by using the test-local helpers.
    #[allow(dead_code)]
    fn _force_oncelock_used() -> &'static OnceLock<()> {
        static X: OnceLock<()> = OnceLock::new();
        &X
    }
}
