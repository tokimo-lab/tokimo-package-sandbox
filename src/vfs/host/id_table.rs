//! Host-side ID allocation: nodeid + fh tables.
//!
//! Each [`FuseHost`](super::FuseHost) owns one `IdTable` shared across all
//! mounts of one sandbox session. Allocation is keyed primarily by
//! `(mount_id, dev, ino)` so two paths to the same inode (e.g. after
//! `link(2)`) collapse to one nodeid — and therefore one kernel-side
//! page cache. Path lookup is a secondary index, used both for
//! resolving an existing nodeid by path and for backends that don't
//! expose `(dev, ino)` (Windows passthrough, in-memory mocks), which
//! degrade gracefully to path-only keying without dedup.
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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use slab::Slab;

#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub mount_id: u32,
    /// All paths currently aliased to this nodeid. The first inserted
    /// path is preferred for resolution stability. Single-link files
    /// keep one element; hard-linked inodes carry one per name.
    pub paths: Vec<PathBuf>,
    /// `(dev, ino)` of the underlying inode, when known. Drives the
    /// dedup index. Path-only-interned entries store `None`.
    pub inode_key: Option<(u64, u64)>,
    /// FUSE lookup count: incremented once per `Lookup` reply that
    /// returns this nodeid, decremented by `Forget(nlookup)`.
    pub refcount: u64,
}

impl NodeEntry {
    /// Pick a representative path for resolution. Always returns the
    /// first inserted (oldest) path so the choice is stable across
    /// alias additions.
    pub fn resolve_path(&self) -> &Path {
        self.paths.first().map(|p| p.as_path()).unwrap_or_else(|| Path::new(""))
    }
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
    /// Inode dedup index: `(mount_id, dev, ino) → nodeid`. Only
    /// populated by [`IdTable::intern_with_inode`]; path-only intern
    /// callsites leave the inode unindexed, so two paths to the same
    /// inode end up with distinct nodeids in that legacy mode.
    by_inode: HashMap<(u32, u64, u64), u64>,
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
        self.inner
            .lock()
            .unwrap_or_else(|e| {
                tracing::warn!("mutex poisoned, recovering: {e}");
                e.into_inner()
            })
            .generation
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
        let inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        let idx = (nodeid - 2) as usize;
        inner.nodes.get(idx).cloned()
    }

    /// Reverse-lookup: find an existing nodeid for `(mount_id, path)`.
    /// Does *not* allocate, does *not* bump refcount. Returns `None`
    /// if the path was never interned (i.e. the guest never `LOOKUP`'d
    /// it — in which case the kernel can't have it cached either, so
    /// no invalidation is required).
    ///
    /// Used by the host-side filesystem watcher to translate a path
    /// it observed changing into the nodeid the guest knows it as.
    pub fn find_path_nodeid(&self, mount_id: u32, path: &Path) -> Option<u64> {
        let inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        inner.by_path.get(&(mount_id, path.to_path_buf())).copied()
    }

    /// Lookup or allocate a nodeid for `(mount_id, path)` *without*
    /// inode dedup. Prefer [`Self::intern_with_inode`] from any
    /// callsite that has already done a stat — this path-only variant
    /// **cannot** participate in hard-link dedup. A subsequent
    /// inode-aware intern of an aliased path will discover the existing
    /// entry only if at least one of the aliases was previously
    /// inode-interned.
    ///
    /// Bumps refcount on hit, allocates on miss. Returns the nodeid and
    /// `true` if it was newly allocated.
    pub fn intern(&self, mount_id: u32, path: PathBuf) -> (u64, bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        if let Some(&nodeid) = inner.by_path.get(&(mount_id, path.clone())) {
            let idx = (nodeid - 2) as usize;
            inner.nodes[idx].refcount += 1;
            return (nodeid, false);
        }
        let entry = NodeEntry {
            mount_id,
            paths: vec![path.clone()],
            inode_key: None,
            refcount: 1,
        };
        let idx = inner.nodes.insert(entry);
        let nodeid = idx as u64 + 2;
        inner.by_path.insert((mount_id, path), nodeid);
        (nodeid, true)
    }

    /// Lookup or allocate a nodeid for `(mount_id, path)` with inode
    /// dedup. Order:
    ///
    /// 1. If `(mount_id, path)` already in `by_path` → bump refcount,
    ///    return existing nodeid, `fresh=false`.
    /// 2. Else if `(mount_id, dev, ino)` already in `by_inode` → bump
    ///    refcount on that nodeid, attach the new path as an alias
    ///    (added to the entry's `paths` set and to `by_path`), return
    ///    the existing nodeid, `fresh=false`.
    /// 3. Else allocate a fresh entry and register it in both indexes.
    ///
    /// If both `dev` and `ino` are zero the call degrades to a
    /// path-only intern (no dedup), matching the behaviour of
    /// [`Self::intern`]. Real Unix inodes are always `> 0`, so this
    /// sentinel cannot collide with a legitimate dedup key.
    pub fn intern_with_inode(&self, mount_id: u32, path: PathBuf, dev: u64, ino: u64) -> (u64, bool) {
        // Sentinel: treat (0, 0) as "no inode info" — fall back to the
        // legacy path-only path so backends without dev/ino plumbing
        // (MemFsVfs, Windows passthrough) don't accidentally alias
        // every path to the same nodeid.
        if dev == 0 && ino == 0 {
            return self.intern(mount_id, path);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });

        // 1. Exact (mount, path) hit.
        if let Some(&nodeid) = inner.by_path.get(&(mount_id, path.clone())) {
            let idx = (nodeid - 2) as usize;
            inner.nodes[idx].refcount += 1;
            // Backfill inode_key if a previous path-only intern landed
            // first: subsequent links can then dedup against this
            // entry instead of allocating a parallel nodeid.
            if inner.nodes[idx].inode_key.is_none() {
                inner.nodes[idx].inode_key = Some((dev, ino));
                inner.by_inode.insert((mount_id, dev, ino), nodeid);
            }
            return (nodeid, false);
        }

        // 2. (mount, dev, ino) hit → alias an existing entry.
        if let Some(&nodeid) = inner.by_inode.get(&(mount_id, dev, ino)) {
            let idx = (nodeid - 2) as usize;
            if let Some(node) = inner.nodes.get_mut(idx) {
                node.refcount += 1;
                if !node.paths.iter().any(|p| p == &path) {
                    node.paths.push(path.clone());
                }
                inner.by_path.insert((mount_id, path), nodeid);
                return (nodeid, false);
            }
            // Stale by_inode entry; drop it and fall through to allocate.
            inner.by_inode.remove(&(mount_id, dev, ino));
        }

        // 3. Fresh allocation.
        let entry = NodeEntry {
            mount_id,
            paths: vec![path.clone()],
            inode_key: Some((dev, ino)),
            refcount: 1,
        };
        let idx = inner.nodes.insert(entry);
        let nodeid = idx as u64 + 2;
        inner.by_path.insert((mount_id, path), nodeid);
        inner.by_inode.insert((mount_id, dev, ino), nodeid);
        (nodeid, true)
    }

    /// Like [`intern`](Self::intern) but does **not** bump refcount.
    /// Used for readdir entries where the kernel won't send `Forget` —
    /// the nodeid stays in the table until a real `Lookup` + `Forget`
    /// cycle releases it.
    pub fn intern_peek(&self, mount_id: u32, path: PathBuf) -> (u64, bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        if let Some(&nodeid) = inner.by_path.get(&(mount_id, path.clone())) {
            return (nodeid, false);
        }

        let entry = NodeEntry {
            mount_id,
            paths: vec![path.clone()],
            inode_key: None,
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
                let paths = node.paths.clone();
                let inode_key = node.inode_key;
                let mid = node.mount_id;
                inner.nodes.remove(old_idx);
                for p in paths {
                    inner.by_path.remove(&(mid, p));
                }
                if let Some((dev, ino)) = inode_key {
                    inner.by_inode.remove(&(mid, dev, ino));
                }
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
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        let idx = (nodeid - 2) as usize;
        let Some(node) = inner.nodes.get_mut(idx) else {
            return;
        };
        if node.refcount == 0 {
            // readdir-allocated entry — remove unconditionally.
            let paths = node.paths.clone();
            let inode_key = node.inode_key;
            let mid = node.mount_id;
            inner.nodes.remove(idx);
            for p in paths {
                inner.by_path.remove(&(mid, p));
            }
            if let Some((dev, ino)) = inode_key {
                inner.by_inode.remove(&(mid, dev, ino));
            }
            return;
        }
        node.refcount = node.refcount.saturating_sub(n);
        if node.refcount == 0 {
            let paths = node.paths.clone();
            let inode_key = node.inode_key;
            let mid = node.mount_id;
            inner.nodes.remove(idx);
            for p in paths {
                inner.by_path.remove(&(mid, p));
            }
            if let Some((dev, ino)) = inode_key {
                inner.by_inode.remove(&(mid, dev, ino));
            }
        }
    }

    /// Drop a single alias path from its owning entry. Used by
    /// `op_unlink` / `op_rmdir` to keep `by_path` in sync with the
    /// underlying filesystem. The nodeid itself is only released once
    /// both the alias set is empty **and** the refcount has reached
    /// zero (the latter happens via [`Self::forget`]).
    ///
    /// No-op if the path isn't currently bound.
    pub fn unbind_path(&self, mount_id: u32, path: &Path) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        let Some(nodeid) = inner.by_path.remove(&(mount_id, path.to_path_buf())) else {
            return;
        };
        let idx = (nodeid - 2) as usize;
        let Some(node) = inner.nodes.get_mut(idx) else {
            return;
        };
        node.paths.retain(|p| p != path);
        if node.paths.is_empty() {
            // Drop the inode index too — the file is gone from this
            // mount, so no future intern should re-find this slot.
            let inode_key = node.inode_key.take();
            let mid = node.mount_id;
            if node.refcount == 0 {
                inner.nodes.remove(idx);
            }
            if let Some((dev, ino)) = inode_key {
                inner.by_inode.remove(&(mid, dev, ino));
            }
        }
    }

    /// Return every nodeid currently referencing the given `(mount_id,
    /// dev, ino)`. Used by the FUSE_NOTIFY_INVAL_INODE path to
    /// invalidate all kernel-side aliases for an inode that was mutated
    /// host-side. In the common (deduped) case this returns at most one
    /// nodeid; the helper exists for backends that couldn't dedup and
    /// therefore have multiple nodeids per inode.
    pub fn nodeids_for_inode(&self, mount_id: u32, dev: u64, ino: u64) -> Vec<u64> {
        if dev == 0 && ino == 0 {
            return Vec::new();
        }
        let inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        // Fast path: by_inode has at most one entry per key (dedup
        // collapses on that key), but a path-only-interned alias may
        // hold a parallel nodeid with no inode_key. Sweep `nodes` to
        // pick those up.
        let mut out: Vec<u64> = Vec::new();
        if let Some(&nid) = inner.by_inode.get(&(mount_id, dev, ino)) {
            out.push(nid);
        }
        for (i, node) in inner.nodes.iter() {
            if node.mount_id == mount_id && node.inode_key == Some((dev, ino)) && !out.contains(&(i as u64 + 2)) {
                out.push(i as u64 + 2);
            }
        }
        out
    }

    /// Re-key any node currently bound to `from` (or any descendant of
    /// `from` if it's a directory) so it now lives under `to`. Called
    /// after a successful rename so subsequent ops on existing nodeids
    /// resolve to the new on-host path.
    ///
    /// Also drops any existing node bound to `to` (overwritten by the
    /// rename target) so it won't shadow the renamed entry.
    pub fn rename_path(&self, mount_id: u32, from: &std::path::Path, to: &std::path::Path) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        // Drop any existing destination binding first — the rename
        // overwrites it. The destination path may be one alias of a
        // multi-link inode; pull just that alias out of its entry.
        if let Some(old_nid) = inner.by_path.remove(&(mount_id, to.to_path_buf())) {
            let idx = (old_nid - 2) as usize;
            if let Some(n) = inner.nodes.get_mut(idx) {
                n.paths.retain(|p| p != to);
                // If the overwritten file was the inode's last alias,
                // also drop the inode-dedup binding so a freshly
                // created file at `to` doesn't accidentally alias this
                // stale slot.
                if n.paths.is_empty() {
                    let inode_key = n.inode_key.take();
                    if let Some((dev, ino)) = inode_key {
                        inner.by_inode.remove(&(mount_id, dev, ino));
                    }
                }
            }
        }

        // Collect path renames (source + any descendants if a dir).
        let to_update: Vec<(u64, std::path::PathBuf, std::path::PathBuf)> = inner
            .by_path
            .iter()
            .filter_map(|((mid, p), &nid)| {
                if *mid != mount_id {
                    return None;
                }
                if p == from {
                    return Some((nid, p.clone(), to.to_path_buf()));
                }
                if let Ok(suffix) = p.strip_prefix(from) {
                    return Some((nid, p.clone(), to.join(suffix)));
                }
                None
            })
            .collect();

        for (nid, old_path, new_path) in to_update {
            inner.by_path.remove(&(mount_id, old_path.clone()));
            inner.by_path.insert((mount_id, new_path.clone()), nid);
            let idx = (nid - 2) as usize;
            if let Some(n) = inner.nodes.get_mut(idx) {
                // Swap the matching alias in-place; preserve other
                // aliases that aren't affected by the rename.
                for p in n.paths.iter_mut() {
                    if *p == old_path {
                        *p = new_path.clone();
                    }
                }
            }
        }
    }

    pub fn alloc_fh(&self, fh: FhEntry) -> u64 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        let idx = inner.fhs.insert(fh);
        idx as u64 + 1
    }

    pub fn take_fh(&self, fh: u64) -> Option<FhEntry> {
        if fh == 0 {
            return None;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
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
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        let idx = (fh - 1) as usize;
        inner.fhs.get_mut(idx).map(f)
    }

    /// Find any open `host_file` (LocalDirVfs fastpath) belonging to the
    /// given `(mount_id, nodeid)`. Used by path-based attribute ops (stat
    /// / setattr) as a fallback when the file has been unlinked but
    /// remains reachable via an open fh — POSIX guarantees the inode is
    /// still alive in this case, so `fstat` on the held `Arc<File>` is
    /// the correct fallback. Without this, [`super::FuseHost::resolve_path`]
    /// would return the empty path for a nodeid whose `paths` vec was
    /// drained by `unbind_path`, and the backend would stat the export
    /// root by mistake — causing the kernel to think the inode flipped
    /// from regular file to directory and refuse subsequent writes.
    pub fn find_open_host_file(&self, mount_id: u32, nodeid: u64) -> Option<Arc<std::fs::File>> {
        let inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("mutex poisoned, recovering: {e}");
            e.into_inner()
        });
        for (_idx, entry) in inner.fhs.iter() {
            if let FhEntry::File {
                mount_id: mid,
                nodeid: nid,
                host_file: Some(hf),
                ..
            } = entry
                && *mid == mount_id
                && *nid == nodeid
            {
                return Some(hf.clone());
            }
        }
        None
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

    // ---- (dev, ino) dedup ----------------------------------------------

    #[test]
    fn inode_dedup_collapses_two_aliases() {
        let t = IdTable::new(1);
        // First link: fresh entry.
        let (nid_a, fresh_a) = t.intern_with_inode(0, PathBuf::from("/a"), 7, 42);
        assert!(fresh_a);
        // Second link to the same inode under a different name: same nodeid.
        let (nid_b, fresh_b) = t.intern_with_inode(0, PathBuf::from("/b"), 7, 42);
        assert!(!fresh_b, "second alias must not allocate a fresh slot");
        assert_eq!(nid_a, nid_b, "hard-linked paths must share a nodeid");

        // Both paths resolve to the same nodeid.
        let n = t.lookup(nid_a).expect("entry present");
        assert_eq!(n.refcount, 2);
        assert_eq!(n.paths.len(), 2);
        assert!(n.paths.iter().any(|p| p == Path::new("/a")));
        assert!(n.paths.iter().any(|p| p == Path::new("/b")));
        assert_eq!(n.inode_key, Some((7, 42)));
        // resolve_path() returns the first inserted path.
        assert_eq!(n.resolve_path(), Path::new("/a"));

        // Refcount drops: one forget keeps the entry alive (refcount 2 → 1).
        t.forget(nid_a, 1);
        assert!(t.lookup(nid_a).is_some());
        t.forget(nid_a, 1);
        // Final forget releases; both by_path entries are cleaned up.
        // Slab may reuse the freed slot for the new allocation — what
        // matters is that the new intern is `fresh`, not that the
        // numeric nodeid differs.
        let (_, fresh_c) = t.intern_with_inode(0, PathBuf::from("/a"), 7, 42);
        assert!(fresh_c);
    }

    #[test]
    fn inode_dedup_zero_falls_back_to_path() {
        let t = IdTable::new(1);
        let (a, fa) = t.intern_with_inode(0, PathBuf::from("/x"), 0, 0);
        let (b, fb) = t.intern_with_inode(0, PathBuf::from("/y"), 0, 0);
        assert!(fa && fb, "(0,0) sentinel must NOT dedup across paths");
        assert_ne!(a, b);
    }

    #[test]
    fn unbind_path_drops_one_alias_only() {
        let t = IdTable::new(1);
        let (nid, _) = t.intern_with_inode(0, PathBuf::from("/a"), 1, 99);
        let (_, _) = t.intern_with_inode(0, PathBuf::from("/b"), 1, 99);
        assert_eq!(t.lookup(nid).unwrap().paths.len(), 2);

        // Unlink /a; the inode is still reachable via /b.
        t.unbind_path(0, Path::new("/a"));
        let n = t.lookup(nid).expect("entry alive: /b still aliases the inode");
        assert_eq!(n.paths, vec![PathBuf::from("/b")]);
        // by_path for /a is gone; intern of /a (fresh stat) does NOT
        // hit the inode index because /b's entry still owns it — but
        // since /b shares inode (1,99), the next stat-aware intern of
        // /a with the same inode does re-alias to the existing nodeid.
        let (nid2, fresh) = t.intern_with_inode(0, PathBuf::from("/a"), 1, 99);
        assert!(!fresh);
        assert_eq!(nid2, nid);
    }

    #[test]
    fn path_only_then_inode_backfills() {
        let t = IdTable::new(1);
        // Legacy path-only intern (e.g. a backend without dev/ino).
        let (nid, _) = t.intern(0, PathBuf::from("/leg"));
        assert_eq!(t.lookup(nid).unwrap().inode_key, None);
        // Re-intern the same path with inode info: same nodeid, but
        // inode_key is backfilled so a *new* alias can dedup later.
        let (nid2, fresh) = t.intern_with_inode(0, PathBuf::from("/leg"), 2, 77);
        assert!(!fresh);
        assert_eq!(nid, nid2);
        assert_eq!(t.lookup(nid).unwrap().inode_key, Some((2, 77)));

        // New alias to the same inode now collapses onto `nid`.
        let (nid3, fresh3) = t.intern_with_inode(0, PathBuf::from("/leg2"), 2, 77);
        assert!(!fresh3);
        assert_eq!(nid3, nid);
    }

    #[test]
    fn nodeids_for_inode_reports_all_aliases() {
        let t = IdTable::new(1);
        let (a, _) = t.intern_with_inode(0, PathBuf::from("/a"), 9, 33);
        // dedup case: same inode key → single nodeid.
        let ids = t.nodeids_for_inode(0, 9, 33);
        assert_eq!(ids, vec![a]);
        // Cross-mount with same (dev, ino) is a separate nodeid.
        let (b, _) = t.intern_with_inode(1, PathBuf::from("/a"), 9, 33);
        assert_ne!(a, b);
        let ids_m1 = t.nodeids_for_inode(1, 9, 33);
        assert_eq!(ids_m1, vec![b]);
    }
}
