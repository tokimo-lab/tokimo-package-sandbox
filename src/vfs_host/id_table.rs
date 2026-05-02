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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

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
        staging: Option<StagingFile>,
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

#[derive(Debug, Default)]
pub struct IdTable {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    nodes: Slab<NodeEntry>,
    by_path: HashMap<(u32, PathBuf), u64>, // value = nodeid
    fhs: Slab<FhEntry>,
    /// Bumped per-process at startup; surfaces in [`crate::vfs_protocol::EntryOut::generation`].
    generation: u64,
}

impl IdTable {
    pub fn new(generation: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                generation,
                ..Default::default()
            }),
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
        if let Some(&nodeid) = inner.by_path.get(&(mount_id, path.clone())) {
            let idx = (nodeid - 2) as usize;
            inner.nodes[idx].refcount += 1;
            return (nodeid, false);
        }
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

    /// Decrement refcount; release the slot when it hits zero.
    pub fn forget(&self, nodeid: u64, n: u64) {
        if nodeid < 2 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let idx = (nodeid - 2) as usize;
        let Some(node) = inner.nodes.get_mut(idx) else {
            return;
        };
        node.refcount = node.refcount.saturating_sub(n);
        if node.refcount == 0 {
            let path = node.path.clone();
            let mid = node.mount_id;
            inner.nodes.remove(idx);
            inner.by_path.remove(&(mid, path));
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
}
