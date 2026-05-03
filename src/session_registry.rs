//! Platform-agnostic session registry.
//!
//! Decouples VM lifecycle from transport connections. A [`SessionRegistry`]
//! maps caller-supplied session IDs (UUIDs) to [`SharedSession`] handles.
//! The session persists across reconnections — dropping a connection does
//! **not** tear down the underlying VM.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Platform-specific session state.
///
/// Each backend (Windows HCS, Linux bwrap, macOS VZ) implements this trait
/// with its own resource handles. The registry only calls [`is_running`] and
/// [`teardown`]; everything else is backend-private.
pub trait SessionState: Send + 'static {
    /// Returns `true` when the VM / sandbox is alive.
    fn is_running(&self) -> bool;

    /// Gracefully shut down and release all resources.
    fn teardown(&mut self);
}

/// A single session's shared state.
///
/// Wrapped in [`Arc`] so the registry, the connection handler, and any
/// background poller threads can all hold a reference without cloning the
/// inner data.
pub struct SharedSession<S: SessionState> {
    pub state: Mutex<S>,
}

/// Thread-safe registry of live sessions, keyed by caller-supplied UUID.
///
/// Cheaply [`Clone`]able — all clones share the same underlying map.
pub struct SessionRegistry<S: SessionState> {
    sessions: Arc<Mutex<HashMap<String, Arc<SharedSession<S>>>>>,
}

impl<S: SessionState> Clone for SessionRegistry<S> {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<S: SessionState> SessionRegistry<S> {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Look up an existing session or create a fresh one.
    ///
    /// If the `session_id` is already present, the existing handle is
    /// returned (the VM may or may not be running — check
    /// [`SharedSession::state`]).  Otherwise a new default-constructed
    /// session is inserted and returned.
    pub fn get_or_create(&self, session_id: &str) -> Arc<SharedSession<S>>
    where
        S: Default,
    {
        let mut map = self.sessions.lock().unwrap();
        map.entry(session_id.to_string())
            .or_insert_with(|| {
                Arc::new(SharedSession {
                    state: Mutex::new(S::default()),
                })
            })
            .clone()
    }

    /// Look up an existing session.  Returns `None` if the ID is unknown.
    pub fn get(&self, session_id: &str) -> Option<Arc<SharedSession<S>>> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    /// Remove a session from the registry.
    ///
    /// The returned `Arc` may still be held by connection threads; the
    /// session is only truly dropped when all references are gone.
    pub fn remove(&self, session_id: &str) -> Option<Arc<SharedSession<S>>> {
        self.sessions.lock().unwrap().remove(session_id)
    }

    /// Number of sessions currently tracked (running or not).
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Returns `true` when no sessions are tracked.
    pub fn is_empty(&self) -> bool {
        self.sessions.lock().unwrap().is_empty()
    }

    /// Snapshot of all `(session_id, SharedSession)` pairs currently
    /// tracked. Cheap because each `SharedSession` is `Arc`-wrapped.
    pub fn entries(&self) -> Vec<(String, Arc<SharedSession<S>>)> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect()
    }
}

impl<S: SessionState> Default for SessionRegistry<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // --- Mock SessionState for testing -----------------------------------

    static TEARDOWN_COUNT: AtomicU32 = AtomicU32::new(0);

    struct MockSession {
        running: AtomicBool,
    }

    impl Default for MockSession {
        fn default() -> Self {
            Self {
                running: AtomicBool::new(false),
            }
        }
    }

    impl SessionState for MockSession {
        fn is_running(&self) -> bool {
            self.running.load(Ordering::Relaxed)
        }

        fn teardown(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            TEARDOWN_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    // --- Tests -----------------------------------------------------------

    #[test]
    fn new_registry_is_empty() {
        let reg = SessionRegistry::<MockSession>::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn get_or_create_inserts_on_first_call() {
        let reg = SessionRegistry::<MockSession>::new();
        let s = reg.get_or_create("sess-1");
        assert_eq!(reg.len(), 1);
        assert!(!s.state.lock().unwrap().is_running());
    }

    #[test]
    fn get_or_create_returns_same_arc_on_second_call() {
        let reg = SessionRegistry::<MockSession>::new();
        let s1 = reg.get_or_create("sess-1");
        s1.state.lock().unwrap().running.store(true, Ordering::Relaxed);

        let s2 = reg.get_or_create("sess-1");
        assert!(Arc::ptr_eq(&s1, &s2));
        assert!(s2.state.lock().unwrap().is_running());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn different_ids_get_different_sessions() {
        let reg = SessionRegistry::<MockSession>::new();
        let s1 = reg.get_or_create("a");
        let s2 = reg.get_or_create("b");
        assert!(!Arc::ptr_eq(&s1, &s2));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn get_returns_none_for_unknown_id() {
        let reg = SessionRegistry::<MockSession>::new();
        assert!(reg.get("nope").is_none());
    }

    #[test]
    fn get_returns_existing_session() {
        let reg = SessionRegistry::<MockSession>::new();
        let s1 = reg.get_or_create("x");
        let s2 = reg.get("x").unwrap();
        assert!(Arc::ptr_eq(&s1, &s2));
    }

    #[test]
    fn remove_returns_session_and_decrements_len() {
        let reg = SessionRegistry::<MockSession>::new();
        reg.get_or_create("x");
        assert_eq!(reg.len(), 1);

        let removed = reg.remove("x");
        assert!(removed.is_some());
        assert_eq!(reg.len(), 0);
        assert!(reg.get("x").is_none());
    }

    #[test]
    fn remove_unknown_returns_none() {
        let reg = SessionRegistry::<MockSession>::new();
        assert!(reg.remove("nope").is_none());
    }

    #[test]
    fn removed_session_survives_while_arc_held() {
        let reg = SessionRegistry::<MockSession>::new();
        let s = reg.get_or_create("x");

        let removed = reg.remove("x").unwrap();
        // Registry no longer tracks it, but the Arc is still alive.
        assert!(reg.get("x").is_none());
        assert_eq!(reg.len(), 0);

        // We can still mutate the session through the held Arc.
        removed.state.lock().unwrap().running.store(true, Ordering::Relaxed);
        assert!(s.state.lock().unwrap().is_running());
    }

    #[test]
    fn session_persists_across_registry_clones() {
        let reg1 = SessionRegistry::<MockSession>::new();
        let reg2 = reg1.clone();

        let s1 = reg1.get_or_create("shared");
        s1.state.lock().unwrap().running.store(true, Ordering::Relaxed);

        let s2 = reg2.get("shared").unwrap();
        assert!(Arc::ptr_eq(&s1, &s2));
        assert!(s2.state.lock().unwrap().is_running());
    }

    #[test]
    fn concurrent_access_from_multiple_threads() {
        let reg = SessionRegistry::<MockSession>::new();
        let mut handles = Vec::new();

        for i in 0..16 {
            let r = reg.clone();
            handles.push(std::thread::spawn(move || {
                let id = format!("sess-{}", i % 4); // 4 unique sessions, 16 threads
                let s = r.get_or_create(&id);
                s.state.lock().unwrap().running.store(true, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Exactly 4 unique sessions should exist.
        assert_eq!(reg.len(), 4);
        for i in 0..4 {
            let s = reg.get(&format!("sess-{i}")).unwrap();
            assert!(s.state.lock().unwrap().is_running());
        }
    }

    #[test]
    fn default_trait_works() {
        let reg = SessionRegistry::<MockSession>::default();
        assert!(reg.is_empty());
    }

    #[test]
    fn empty_session_id_is_a_valid_key() {
        let reg = SessionRegistry::<MockSession>::new();
        let s = reg.get_or_create("");
        assert_eq!(reg.len(), 1);
        assert!(Arc::ptr_eq(&s, &reg.get("").unwrap()));
    }
}
