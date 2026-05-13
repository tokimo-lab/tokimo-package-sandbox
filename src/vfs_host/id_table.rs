//! Host-side ID allocation: nodeid + fh tables.
//!
//! Each [`FuseHost`](super::FuseHost) owns one `IdTable` shared across all
//! mounts of one sandbox session. Allocation is keyed by `(mount_id,
//! path)` so opening the same file twice returns the same nodeid.
//!
//! # Layout
//!
//! - `nodeid == 1` is reserved as the "session root"; in the FUSE bridge
//!   each mount appears under its own connection so the per-connection
//!   root is always `1`. We treat `(mount_id, "/")` as nodeid `1` for
//!   the relevant connection.
//! - `nodeid >= 2` are slab indices + 2 (so 0 ≠ valid nodeid and 1 is
//!   reserved root).
//! - `fh` are slab indices + 1 (so 0 ≠ valid fh).
//!
//! The slab approach gives O(1) allocate / lookup / release with
//! amortized 0 alloc once steady-state.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use slab::Slab;

#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub mount_id: u32,
    pub path: PathBuf,
    /// FUSE lookup count: incremented once per `Lookup` reply that
    /// returns this nodeid, decremented by `Forget(nlookup)`.
    pub refcount: u64,
}

#[derive(Debug)]
pub enum FhEntry {
    Dir {
        mount_id: u32,
        nodeid: u64,
        /// Snapshot of directory entries taken at `OpenDir` time.
        /// `(nodeid, name, kind, size)` — nodeid is allocated lazily on
        /// `Lookup`.
        entries: Vec<(String, super::DirSnapshot)>,
    },
    File {
        mount_id: u32,
        nodeid: u64,
        flags: u32,
        /// Set on first write. Path-on-host of the staging tempfile.
        /// `Release`/`Flush` drains this into the backend.
        ///
        /// Mutually exclusive with `host_file` — a fh either uses the
        /// fast direct-IO path (LocalDirVfs) or the staging path
        /// (everything else).
        staging: Option<StagingFile>,
        /// Direct host-file fastpath: when the backend exposes
        /// `as_resolve_local()`, [`super::FuseHost::op_open`] opens the
        /// real on-disk file once and stashes it here. `op_read` /
        /// `op_write` then do `pread` / `pwrite` directly, skipping the
        /// staging-tempfile dance entirely. Reduces big writes from
        /// O(N) tempfile bytes + read-back + put → O(N) pwrite.
        host_file: Option<Arc<std::fs::File>>,
    },
}

/// Per-fh write staging buffer. We collect random-write bytes into a
/// local tempfile and flush as one stream on `Release`/`Flush` — VFS
/// `Driver` doesn't expose random-write APIs.
#[derive(Debug)]
pub struct StagingFile {
    pub path: PathBuf,
    pub file: std::fs::File,
    pub max_offset: u64,
    pub dirty: bool,
}

/// Default capacity for cold refcount=0 entry cache.
/// Bounds memory usage for large directories while preserving recently listed entries.
const DEFAULT_COLD_CAP: usize = 4096;

#[derive(Debug)]
pub struct IdTable {
    inner: Mutex<Inner>,
    cold_cap: usize,
}

#[derive(Debug, Default)]
struct Inner {
    nodes: Slab<NodeEntry>,
    by_path: HashMap<(u32, PathBuf), u64>, // value = nodeid
    fhs: Slab<FhEntry>,
    /// Bumped per-process at startup; surfaces in [`crate::vfs_protocol::EntryOut::generation`].
    generation: u64,
    /// Queue of refcount=0 entries in insertion order. May contain stale ids.
    cold_queue: VecDeque<u64>,
}

impl IdTable {
    pub fn new(generation: u64) -> Self {
        Self::with_cold_cap(generation, DEFAULT_COLD_CAP)
    }

    /// Create an IdTable with a custom cold entry cap (for testing).
    pub fn with_cold_cap(generation: u64, cold_cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                generation,
                ..Default::default()
            }),
            cold_cap,
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }

    /// Resolve a `nodeid` to its mount + path. `nodeid == 1` is the
    /// per-connection root; the caller passes `(mount_id, "/")` for it.
    pub fn lookup(&self, nodeid: u64) -> Option<NodeEntry> {
        if nodeid == 0 {
            return None;
        }
        if nodeid == 1 {
            // Caller's responsibility — they know the mount_id.
            return None;
        }
        let inner = self.inner.lock().unwrap();
        let idx = (nodeid - 2) as usize;
        inner.nodes.get(idx).cloned()
    }

    /// Lookup or allocate a nodeid for `(mount_id, path)`. Returns the
    /// nodeid and `true` if it was newly allocated. Bumps refcount.
    pub fn intern(&self, mount_id: u32, path: PathBuf) -> (u64, bool) {
        let mut inner = self.inner.lock().unwrap();
        // get() borrows a temporary — path is NOT moved, usable afterward.
        if let Some(&nodeid) = inner.by_path.get(&(mount_id, path.clone())) {
            let idx = (nodeid - 2) as usize;
            inner.nodes[idx].refcount += 1;
            return (nodeid, false);
        }
        // Slow path: one clone for the NodeEntry, then move into HashMap.
        let entry = NodeEntry {
            mount_id,
            path: path.clone(),
            refcount: 1,
        };
        let idx = inner.nodes.insert(entry);
        let nodeid = idx as u64 + 2;
        inner.by_path.insert((mount_id, path), nodeid);
        (nodeid, true)
    }

    /// Like [`intern`](Self::intern) but does **not** bump refcount.
    /// Used for readdir entries where the kernel won't send `Forget` —
    /// the nodeid stays in the table until a real `Lookup` + `Forget`
    /// cycle releases it.
    pub fn intern_peek(&self, mount_id: u32, path: PathBuf) -> (u64, bool) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&nodeid) = inner.by_path.get(&(mount_id, path.clone())) {
            return (nodeid, false);
        }

        let entry = NodeEntry {
            mount_id,
            path: path.clone(),
            refcount: 0,
        };
        let idx = inner.nodes.insert(entry);
        let nodeid = idx as u64 + 2;
        inner.by_path.insert((mount_id, path), nodeid);

        // Remove any stale queue entries for this nodeid (from previous forget+reuse).
        inner.cold_queue.retain(|&id| id != nodeid);

        // Enqueue the new cold entry.
        inner.cold_queue.push_back(nodeid);

        // Lazy eviction: pop oldest entries until under cap.
        while inner.cold_queue.len() > self.cold_cap {
            let Some(old_id) = inner.cold_queue.pop_front() else {
                break;
            };
            let old_idx = (old_id - 2) as usize;
            // Skip if missing (stale) or refcount > 0 (upgraded).
            if let Some(node) = inner.nodes.get(old_idx)
                && node.refcount == 0
            {
                let path = node.path.clone();
                let mid = node.mount_id;
                inner.nodes.remove(old_idx);
                inner.by_path.remove(&(mid, path));
            }
        }

        (nodeid, true)
    }

    /// Decrement refcount; release the slot when it hits zero.
    ///
    /// Entries with `refcount == 0` (created by [`intern_peek`](Self::intern_peek)
    /// for readdir) are removed immediately — the kernel is telling us it
    /// no longer holds a reference, so the slab entry can be freed.
    pub fn forget(&self, nodeid: u64, n: u64) {
        if nodeid < 2 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let idx = (nodeid - 2) as usize;
        let Some(node) = inner.nodes.get_mut(idx) else {
            return;
        };
        if node.refcount == 0 {
            // readdir-allocated entry — remove unconditionally.
            let path = node.path.clone();
            let mid = node.mount_id;
            inner.nodes.remove(idx);
            inner.by_path.remove(&(mid, path));
            return;
        }
        node.refcount = node.refcount.saturating_sub(n);
        if node.refcount == 0 {
            let path = node.path.clone();
            let mid = node.mount_id;
            inner.nodes.remove(idx);
            inner.by_path.remove(&(mid, path));
        }
    }

    /// Re-key any node currently bound to `from` (or any descendant of
    /// `from` if it's a directory) so it now lives under `to`. Called
    /// after a successful rename so subsequent ops on existing nodeids
    /// resolve to the new on-host path.
    ///
    /// Also drops any existing node bound to `to` (overwritten by the
    /// rename target) so it won't shadow the renamed entry.
    pub fn rename_path(&self, mount_id: u32, from: &std::path::Path, to: &std::path::Path) {
        let mut inner = self.inner.lock().unwrap();
        // Drop any existing destination binding first — the rename
        // overwrites it. Its slot is left in `nodes` until the kernel
        // forgets it, but the by_path lookup must not return the stale
        // nodeid for the new file.
        if let Some(old_nid) = inner.by_path.remove(&(mount_id, to.to_path_buf())) {
            let idx = (old_nid - 2) as usize;
            if let Some(n) = inner.nodes.get_mut(idx) {
                // Mark it as moved-away so it won't accidentally serve
                // the overwriting file under its original nodeid; the
                // path field is otherwise unused by lookups but is read
                // by op_* helpers. Pointing it at the destination is
                // wrong (would alias the renamed-in node); blank it.
                n.path = std::path::PathBuf::new();
            }
        }

        // Collect nodes to re-key (source path + any descendants).
        let to_update: Vec<(u64, std::path::PathBuf)> = inner
            .by_path
            .iter()
            .filter_map(|((mid, p), &nid)| {
                if *mid != mount_id {
                    return None;
                }
                if p == from {
                    return Some((nid, to.to_path_buf()));
                }
                if let Ok(suffix) = p.strip_prefix(from) {
                    return Some((nid, to.join(suffix)));
                }
                None
            })
            .collect();

        for (nid, new_path) in to_update {
            let idx = (nid - 2) as usize;
            // Remove old binding.
            if let Some(n) = inner.nodes.get(idx) {
                let old_path = n.path.clone();
                inner.by_path.remove(&(mount_id, old_path));
            }
            // Insert new binding.
            inner.by_path.insert((mount_id, new_path.clone()), nid);
            if let Some(n) = inner.nodes.get_mut(idx) {
                n.path = new_path;
            }
        }
    }

    pub fn alloc_fh(&self, fh: FhEntry) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        let idx = inner.fhs.insert(fh);
        idx as u64 + 1
    }

    pub fn take_fh(&self, fh: u64) -> Option<FhEntry> {
        if fh == 0 {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();
        let idx = (fh - 1) as usize;
        if inner.fhs.contains(idx) {
            Some(inner.fhs.remove(idx))
        } else {
            None
        }
    }

    /// Run a closure with an `&mut FhEntry` while holding the lock.
    /// Returns `None` if the fh is unknown.
    pub fn with_fh_mut<R>(&self, fh: u64, f: impl FnOnce(&mut FhEntry) -> R) -> Option<R> {
        if fh == 0 {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();
        let idx = (fh - 1) as usize;
        inner.fhs.get_mut(idx).map(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_and_forget() {
        let t = IdTable::new(1);
        let (a, fresh) = t.intern(0, PathBuf::from("/foo"));
        assert!(fresh);
        let (b, fresh2) = t.intern(0, PathBuf::from("/foo"));
        assert!(!fresh2);
        assert_eq!(a, b);
        // refcount = 2; first forget keeps it
        t.forget(a, 1);
        assert!(t.lookup(a).is_some());
        // second forget releases
        t.forget(a, 1);
        assert!(t.lookup(a).is_none());
        // re-intern → may reuse slot or not, but path mapping should work
        let (c, fresh3) = t.intern(0, PathBuf::from("/foo"));
        assert!(fresh3);
        assert!(c >= 2);
    }

    #[test]
    fn fh_roundtrip() {
        let t = IdTable::new(1);
        let fh = t.alloc_fh(FhEntry::Dir {
            mount_id: 0,
            nodeid: 2,
            entries: vec![],
        });
        assert!(fh >= 1);
        assert!(t.take_fh(fh).is_some());
        assert!(t.take_fh(fh).is_none());
    }

    #[test]
    fn intern_peek_reuses_existing() {
        let t = IdTable::new(1);
        // First peek allocates with refcount=0.
        let (a, fresh) = t.intern_peek(0, PathBuf::from("/bar"));
        assert!(fresh);
        assert!(t.lookup(a).is_some());
        // Second peek reuses the same nodeid without bumping refcount.
        let (b, fresh2) = t.intern_peek(0, PathBuf::from("/bar"));
        assert!(!fresh2);
        assert_eq!(a, b);
        // forget on refcount=0 entry removes it.
        t.forget(a, 1);
        assert!(t.lookup(a).is_none());
        // Re-peek allocates a new entry.
        let (c, fresh3) = t.intern_peek(0, PathBuf::from("/bar"));
        assert!(fresh3);
        assert!(c >= 2);
    }

    #[test]
    fn intern_bumps_refcount_on_peek_entry() {
        let t = IdTable::new(1);
        let (a, _) = t.intern_peek(0, PathBuf::from("/baz"));
        assert_eq!(t.lookup(a).unwrap().refcount, 0);
        // intern bumps refcount from 0 → 1.
        let (b, fresh) = t.intern(0, PathBuf::from("/baz"));
        assert!(!fresh);
        assert_eq!(a, b);
        assert_eq!(t.lookup(a).unwrap().refcount, 1);
        // forget decrements to 0 → removes.
        t.forget(a, 1);
        assert!(t.lookup(a).is_none());
    }

    #[test]
    fn cold_cap_evicts_oldest_when_full() {
        let t = IdTable::with_cold_cap(1, 3);

        // Allocate 3 cold entries (at cap)
        let (a, _) = t.intern_peek(0, PathBuf::from("/cold1"));
        let (b, _) = t.intern_peek(0, PathBuf::from("/cold2"));
        let (c, _) = t.intern_peek(0, PathBuf::from("/cold3"));

        // All should exist
        assert!(t.lookup(a).is_some());
        assert!(t.lookup(b).is_some());
        assert!(t.lookup(c).is_some());

        // Allocate one more entry, pushing past cap
        let (d, _) = t.intern_peek(0, PathBuf::from("/cold4"));

        // Oldest (a) should be evicted
        assert!(t.lookup(a).is_none());
        assert!(t.lookup(b).is_some());
        assert!(t.lookup(c).is_some());
        assert!(t.lookup(d).is_some());
    }

    #[test]
    fn upgraded_entry_survives_eviction() {
        let t = IdTable::with_cold_cap(1, 3);

        // Allocate one cold entry
        let (a, _) = t.intern_peek(0, PathBuf::from("/upgrade"));
        assert_eq!(t.lookup(a).unwrap().refcount, 0);

        // Upgrade it to refcount=1
        let (a2, fresh) = t.intern(0, PathBuf::from("/upgrade"));
        assert_eq!(a, a2);
        assert!(!fresh);
        assert_eq!(t.lookup(a).unwrap().refcount, 1);

        // Fill the cap and go beyond
        t.intern_peek(0, PathBuf::from("/cold1"));
        t.intern_peek(0, PathBuf::from("/cold2"));
        t.intern_peek(0, PathBuf::from("/cold3"));
        t.intern_peek(0, PathBuf::from("/cold4"));
        t.intern_peek(0, PathBuf::from("/cold5"));

        // Upgraded entry should still exist with refcount=1
        assert!(t.lookup(a).is_some());
        assert_eq!(t.lookup(a).unwrap().refcount, 1);

        // Verify path mapping still works
        let (a3, fresh2) = t.intern(0, PathBuf::from("/upgrade"));
        assert_eq!(a, a3);
        assert!(!fresh2);
        assert_eq!(t.lookup(a).unwrap().refcount, 2);
    }

    #[test]
    fn forgotten_entry_eviction_safe() {
        let t = IdTable::with_cold_cap(1, 3);

        t.intern_peek(0, PathBuf::from("/old1"));
        t.intern_peek(0, PathBuf::from("/old2"));
        t.intern_peek(0, PathBuf::from("/old3"));

        let (a, _) = t.intern_peek(0, PathBuf::from("/forgotten"));
        t.forget(a, 1);

        // Slab may reuse the freed slot for this new entry.
        let (reused, _) = t.intern_peek(0, PathBuf::from("/reused"));

        t.intern_peek(0, PathBuf::from("/new1"));
        t.intern_peek(0, PathBuf::from("/new2"));

        // Reused entry should survive eviction and path mapping should work.
        assert!(t.lookup(reused).is_some());
        let (reused2, fresh) = t.intern_peek(0, PathBuf::from("/reused"));
        assert_eq!(reused, reused2);
        assert!(!fresh);
    }
}
