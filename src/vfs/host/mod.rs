//! FUSE-over-vsock host: dispatches wire requests to [`VfsBackend`]
//! implementations.
//!
//! # Lifecycle
//!
//! ```text
//!                 ┌──────────────────────────────────────────────┐
//!                 │  FuseHost                                    │
//!                 │   ├─ mounts: Vec<MountEntry>     (mount_id↔Backend)
//!                 │   └─ id_table: IdTable           (nodeid + fh)
//!                 └──────────────────────────────────────────────┘
//!                              ▲
//!                              │  serve(stream)   one task per connection
//!                              │
//!     accept_loop  ─────────► AsyncRead+AsyncWrite duplex (vsock / unix)
//! ```
//!
//! Per connection the protocol is symmetric:
//!
//! 1. Read [`Frame::Hello`] → reply [`Frame::HelloAck`].
//! 2. Loop: read `Request{req_id, mount_id, op}` → spawn handler →
//!    write `Response{req_id, result}`.
//! 3. EOF → drop fhs owned by this connection, exit task.
//!
//! Concurrent in-flight requests are allowed; the writer is serialised
//! via a `Mutex<TxHalf>`.

mod helpers;
pub mod id_table;
mod ops;
mod watcher;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

use crate::vfs_backend::{SharedVfsBackend, VfsError};
use crate::vfs_protocol::wire::{read_frame, write_frame};
use crate::vfs_protocol::{Frame, Inval, NodeKind, Req, Res, StatfsOut, errno_for};
use helpers::op_is_cheap;
use id_table::{FhEntry, IdTable};

/// Lightweight clone of [`VfsFileInfo`](crate::vfs_backend::VfsFileInfo)
/// used inside `FhEntry::Dir` snapshots. Carries enough metadata for
/// both `ReadDir` (just kind) and `ReadDirPlus` (full attrs) without
/// re-stat'ing.
#[derive(Debug, Clone)]
pub struct DirSnapshot {
    pub kind: NodeKind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub rdev: u32,
    /// Underlying `(dev, ino)` pair, when the backend exposed it via
    /// [`VfsFileInfo::dev`](crate::vfs_backend::VfsFileInfo::dev) /
    /// [`VfsFileInfo::ino`](crate::vfs_backend::VfsFileInfo::ino). Used
    /// to dedup hard-linked children at readdirplus time.
    pub dev: u64,
    pub ino: u64,
}

// ---------------------------------------------------------------------------
// FuseHost
// ---------------------------------------------------------------------------

/// One [`FuseHost`] per sandbox session: a registry of mounts plus the
/// per-connection serve loop.
pub struct FuseHost {
    mounts: parking_lot_compat::RwLock<Vec<Option<MountEntry>>>,
    id_table: IdTable,
    /// Per-connection notification senders. Each [`Self::serve`] task
    /// registers one on Hello and removes it on drop. Used by
    /// [`Self::notify_inode`] / [`Self::notify_entry`] to push
    /// `Frame::Notify(Inval::*)` to the guest kernel for cache
    /// invalidation when a host-side mutation could leave an aliased
    /// nodeid stale.
    notifiers: parking_lot_compat::RwLock<Vec<NotifyEntry>>,
    next_notifier_id: AtomicU64,
}

#[derive(Clone)]
struct NotifyEntry {
    id: u64,
    /// `None` = wildcard (matches every mount). Bound at handshake to
    /// the mount the client requested in `Hello.mount_name`; if the
    /// client passed no mount_name, we leave this `None` and let the
    /// guest's nodeid space (allocated by the same IdTable) discriminate.
    mount_id: Option<u32>,
    tx: mpsc::UnboundedSender<Inval>,
}

#[derive(Clone)]
pub(in crate::vfs::host) struct MountEntry {
    name: String,
    pub(in crate::vfs::host) backend: SharedVfsBackend,
    pub(in crate::vfs::host) read_only: bool,
    /// External-mutation watcher (inotify/FSEvents/RDCW). Some when the
    /// backend exposed a `watch_root()`. Wrapped in `Arc` so the
    /// MountEntry can be `Clone` (`get_mount` returns owned copies);
    /// only the originally-registered slot drops the inner handle when
    /// removed, which stops the underlying OS subscription.
    pub(in crate::vfs::host) watcher: Option<Arc<watcher::WatcherHandle>>,
}

impl Default for FuseHost {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseHost {
    pub fn new() -> Self {
        // Generation: combine wall-clock + a monotonically incrementing
        // counter so two FuseHosts created in the same nanosecond still
        // get distinct generations. Used so stale FUSE handles from a
        // previous host instance get ESTALE.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let now_ns = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let bump = COUNTER.fetch_add(1, Ordering::Relaxed);
        let generation = now_ns.rotate_left(13) ^ bump.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        Self {
            mounts: parking_lot_compat::RwLock::new(Vec::new()),
            id_table: IdTable::new(generation),
            notifiers: parking_lot_compat::RwLock::new(Vec::new()),
            next_notifier_id: AtomicU64::new(1),
        }
    }

    /// Register a mount and return its `mount_id`. The id is stable for
    /// the lifetime of the slot; [`Self::remove_mount`] frees it for
    /// reuse.
    ///
    /// If `backend.watch_root()` returns `Some`, this also spawns an
    /// inotify/FSEvents/RDCW watcher whose lifetime is tied to the
    /// mount slot — `remove_mount` stops it. Takes `&Arc<Self>` because
    /// the watcher needs a weak reference back to the host to push
    /// invalidation frames.
    pub fn register_mount(
        self: &Arc<Self>,
        name: impl Into<String>,
        backend: SharedVfsBackend,
        read_only: bool,
    ) -> u32 {
        let watch_root = backend.watch_root();
        let mut mounts = self.mounts.write();
        // Prefer reusing a free slot.
        let mount_id = if let Some((i, slot)) = mounts.iter_mut().enumerate().find(|(_, slot)| slot.is_none()) {
            *slot = Some(MountEntry {
                name: name.into(),
                backend,
                read_only,
                watcher: None,
            });
            i as u32
        } else {
            mounts.push(Some(MountEntry {
                name: name.into(),
                backend,
                read_only,
                watcher: None,
            }));
            (mounts.len() - 1) as u32
        };
        drop(mounts);

        if let Some(root) = watch_root
            && let Some(handle) = watcher::spawn_watcher(self.clone(), mount_id, root)
        {
            let mut mounts = self.mounts.write();
            if let Some(Some(entry)) = mounts.get_mut(mount_id as usize) {
                entry.watcher = Some(Arc::new(handle));
            }
        }
        mount_id
    }

    pub fn remove_mount(&self, mount_id: u32) -> Option<String> {
        let mut mounts = self.mounts.write();
        mounts
            .get_mut(mount_id as usize)
            .and_then(|slot| slot.take())
            .map(|m| m.name)
    }

    pub fn mount_id_by_name(&self, name: &str) -> Option<u32> {
        self.mounts
            .read()
            .iter()
            .position(|slot| matches!(slot, Some(m) if m.name == name))
            .map(|i| i as u32)
    }

    pub(in crate::vfs::host) fn get_mount(&self, mount_id: u32) -> Option<MountEntry> {
        self.mounts.read().get(mount_id as usize).and_then(|slot| slot.clone())
    }

    /// Serve one host↔guest connection until EOF. Caller is responsible
    /// for spawning this on a tokio task.
    pub async fn serve<S>(self: Arc<Self>, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut rx, tx) = tokio::io::split(stream);
        let tx = Arc::new(AsyncMutex::new(tx));

        // 1. Hello handshake.
        let (max_inflight, bound_mount_id) = {
            let mut guard = tx.lock().await;
            match crate::vfs_protocol::handshake::server_handshake(&mut rx, &mut *guard, |n| self.mount_id_by_name(n))
                .await?
            {
                Some(mi) => mi,
                None => return Ok(()),
            }
        };

        let _ = max_inflight; // backpressure not enforced server-side yet

        // 1a. Register a notification sender for this connection. A
        // dedicated writer task owns the receiver end and shares the
        // serialized `tx` mutex with the request-response path; this
        // keeps the read loop simple (no tokio::select! interleaving).
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<Inval>();
        let notifier_id = {
            let id = self.next_notifier_id.fetch_add(1, Ordering::Relaxed);
            self.notifiers.write().push(NotifyEntry {
                id,
                mount_id: bound_mount_id,
                tx: notify_tx,
            });
            id
        };
        let notify_writer = {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(inval) = notify_rx.recv().await {
                    let mut tx_guard = tx.lock().await;
                    if let Err(e) = write_frame(&mut *tx_guard, &Frame::Notify(inval)).await {
                        tracing::warn!("vfs_host: write notify failed: {e}");
                        break;
                    }
                }
            })
        };
        // RAII guard: drop our notifier registration + abort the writer
        // task when this serve loop exits for any reason.
        struct NotifyGuard {
            host: Arc<FuseHost>,
            id: u64,
            writer: tokio::task::JoinHandle<()>,
        }
        impl Drop for NotifyGuard {
            fn drop(&mut self) {
                self.host.notifiers.write().retain(|e| e.id != self.id);
                self.writer.abort();
            }
        }
        let _notify_guard = NotifyGuard {
            host: self.clone(),
            id: notifier_id,
            writer: notify_writer,
        };

        // 2. Steady state.
        loop {
            let frame = read_frame(&mut rx).await?;
            let Some(frame) = frame else { return Ok(()) };
            match frame {
                Frame::Request { req_id, mount_id, op } => {
                    // Cheap ops complete in tens of µs and benefit from
                    // skipping the tokio::spawn task allocation + scheduler
                    // hop. Heavy ops (real I/O, dir listing) get their own
                    // task so they don't block reading the next frame.
                    if op_is_cheap(&op) {
                        let result = self.clone().dispatch(mount_id, op).await;
                        let mut tx_guard = tx.lock().await;
                        if let Err(e) = write_frame(&mut *tx_guard, &Frame::Response { req_id, result }).await {
                            tracing::warn!("vfs_host: write response failed: {e}");
                        }
                    } else {
                        let host = self.clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let result = host.dispatch(mount_id, op).await;
                            let mut tx_guard = tx.lock().await;
                            if let Err(e) = write_frame(&mut *tx_guard, &Frame::Response { req_id, result }).await {
                                tracing::warn!("vfs_host: write response failed: {e}");
                            }
                        });
                    }
                }
                Frame::Hello { .. } | Frame::HelloAck { .. } => {
                    tracing::warn!("vfs_host: stray Hello in steady state, ignoring");
                }
                Frame::Response { .. } | Frame::Notify(_) => {
                    tracing::warn!("vfs_host: client sent Response/Notify, ignoring");
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Op dispatcher
    // -----------------------------------------------------------------

    async fn dispatch(self: Arc<Self>, mount_id: u32, op: Req) -> Res {
        match op {
            Req::Lookup { parent_nodeid, name } => self.op_lookup(mount_id, parent_nodeid, &name).await,
            Req::Forget { nodeid, nlookup } => {
                self.id_table.forget(nodeid, nlookup);
                Res::Ok
            }
            Req::GetAttr { nodeid } => self.op_getattr(mount_id, nodeid).await,
            Req::SetAttr {
                nodeid,
                mode,
                size,
                atime,
                mtime,
            } => self.op_setattr(mount_id, nodeid, mode, size, atime, mtime).await,
            Req::OpenDir { nodeid } => self.op_opendir(mount_id, nodeid).await,
            Req::ReadDir { fh, offset } => self.op_readdir(fh, offset).await,
            Req::ReadDirPlus { fh, offset } => self.op_readdirplus(fh, offset).await,
            Req::ReleaseDir { fh } => {
                self.id_table.take_fh(fh);
                Res::Ok
            }
            Req::Open { nodeid, flags } => self.op_open(mount_id, nodeid, flags).await,
            Req::Read { fh, offset, size } => self.op_read(fh, offset, size).await,
            Req::Write { fh, offset, data } => self.op_write(fh, offset, data).await,
            Req::Flush { fh } => self.op_flush(fh).await,
            Req::Release { fh } => self.op_release(fh).await,
            Req::Mkdir {
                parent_nodeid,
                name,
                mode,
            } => self.op_mkdir(mount_id, parent_nodeid, &name, mode).await,
            Req::Mknod {
                parent_nodeid,
                name,
                mode,
                rdev,
            } => self.op_mknod(mount_id, parent_nodeid, &name, mode, rdev).await,
            Req::Create {
                parent_nodeid,
                name,
                mode,
            } => self.op_create(mount_id, parent_nodeid, &name, mode).await,
            Req::Rmdir { parent_nodeid, name } => self.op_rmdir(mount_id, parent_nodeid, &name).await,
            Req::Unlink { parent_nodeid, name } => self.op_unlink(mount_id, parent_nodeid, &name).await,
            Req::Rename {
                old_parent,
                old_name,
                new_parent,
                new_name,
            } => {
                self.op_rename(mount_id, old_parent, &old_name, new_parent, &new_name)
                    .await
            }
            Req::Statfs { nodeid: _ } => Res::Statfs(StatfsOut {
                blocks: 1 << 30,
                bfree: 1 << 30,
                bavail: 1 << 30,
                files: 1 << 20,
                ffree: 1 << 20,
                bsize: 4096,
                namelen: 255,
                frsize: 4096,
            }),
            Req::Symlink {
                parent_nodeid,
                name,
                target,
            } => self.op_symlink(mount_id, parent_nodeid, &name, &target).await,
            Req::Readlink { nodeid } => self.op_readlink(mount_id, nodeid).await,

            // ---- v3 ----
            Req::Link {
                nodeid,
                new_parent,
                new_name,
            } => self.op_link(mount_id, nodeid, new_parent, &new_name).await,
            Req::Fsync { fh, datasync } => self.op_fsync(fh, datasync).await,
            Req::Fsyncdir { fh, datasync } => self.op_fsyncdir(fh, datasync).await,
            Req::Setxattr {
                nodeid,
                name,
                value,
                flags,
            } => self.op_setxattr(mount_id, nodeid, &name, value, flags).await,
            Req::Getxattr { nodeid, name, size } => self.op_getxattr(mount_id, nodeid, &name, size).await,
            Req::Listxattr { nodeid, size } => self.op_listxattr(mount_id, nodeid, size).await,
            Req::Removexattr { nodeid, name } => self.op_removexattr(mount_id, nodeid, &name).await,
            Req::Access { nodeid, mask } => self.op_access(mount_id, nodeid, mask).await,
            Req::Fallocate {
                fh,
                offset,
                length,
                mode,
            } => self.op_fallocate(fh, offset, length, mode).await,
            Req::CopyFileRange {
                fh_in,
                off_in,
                fh_out,
                off_out,
                len,
                flags,
            } => {
                self.op_copy_file_range(fh_in, off_in, fh_out, off_out, len, flags)
                    .await
            }
            Req::Getlk { fh, owner, lk } => self.op_getlk(fh, owner, lk).await,
            Req::Setlk { fh, owner, lk, sleep } => self.op_setlk(fh, owner, lk, sleep).await,
            Req::Lseek { fh, offset, whence } => self.op_lseek(fh, offset, whence).await,
            Req::Bmap { nodeid, blocksize, idx } => self.op_bmap(mount_id, nodeid, blocksize, idx).await,
            Req::Ioctl {
                fh,
                cmd,
                arg,
                in_data,
                out_size,
                flags,
            } => self.op_ioctl(fh, cmd, arg, in_data, out_size, flags).await,
            Req::Poll { fh, events, flags } => self.op_poll(fh, events, flags).await,
        }
    }

    // -----------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------

    /// Translate `(mount_id, nodeid)` to a vfs-relative path. `nodeid==1`
    /// is always the export root `/`.
    ///
    /// Returns `Res::Error(ENOENT)` when the nodeid is alive (e.g. still
    /// held by an open fh) but all its path aliases were dropped by
    /// `unbind_path` (the file was unlinked). Callers that have a fh
    /// fallback (op_getattr / op_setattr) should handle this and reply
    /// via `fstat` on the open `host_file` — POSIX guarantees the inode
    /// is still alive. Without this, [`NodeEntry::resolve_path`] would
    /// return `""` and the backend would happily stat the export root
    /// instead, returning directory attrs that flip the kernel's view of
    /// the inode from regular file to directory and break subsequent
    /// writes with EIO (apt's mkstemp+unlink+write pattern).
    pub(in crate::vfs::host) fn resolve_path(&self, mount_id: u32, nodeid: u64) -> Result<PathBuf, Res> {
        if nodeid == 1 {
            return Ok(PathBuf::from("/"));
        }
        let n = self
            .id_table
            .lookup(nodeid)
            .ok_or_else(|| Res::Error(errno_for(&VfsError::InvalidArgument(format!("stale nodeid {nodeid}")))))?;
        if n.mount_id != mount_id {
            return Err(Res::Error(errno_for(&VfsError::InvalidArgument(
                "nodeid/mount_id mismatch".into(),
            ))));
        }
        if n.paths.is_empty() {
            return Err(Res::Error(errno_for(&VfsError::NotFound)));
        }
        Ok(n.resolve_path().to_path_buf())
    }

    pub(in crate::vfs::host) fn child_path(parent: &Path, name: &str) -> PathBuf {
        if parent == Path::new("/") {
            PathBuf::from(format!("/{name}"))
        } else {
            let mut p = parent.to_path_buf();
            p.push(name);
            p
        }
    }

    // -----------------------------------------------------------------
    // Notification fan-out (FUSE_NOTIFY_INVAL_INODE / INVAL_ENTRY)
    // -----------------------------------------------------------------

    /// Look up the `(mount_id, dev, ino)` triple for an open fh. Used
    /// by fh-based mutating ops to decide whether the post-mutation
    /// state requires a cross-alias invalidate.
    pub(in crate::vfs::host) fn fh_inode_key(&self, fh: u64) -> Option<(u32, u64, u64)> {
        let (mount_id, nodeid) = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File { mount_id, nodeid, .. } => Some((*mount_id, *nodeid)),
            _ => None,
        })??;
        let node = self.id_table.lookup(nodeid)?;
        let (dev, ino) = node.inode_key?;
        Some((mount_id, dev, ino))
    }

    /// Fire `FUSE_NOTIFY_INVAL_INODE` for every aliased nodeid of
    /// `(mount_id, dev, ino)` — but only when at least two aliases
    /// exist. The single-alias common case relies on the kernel page
    /// cache being consistent with our own writes through that nodeid,
    /// so there's nothing to invalidate.
    ///
    /// Backends that don't expose `(dev, ino)` (typically returning
    /// `(0, 0)`) short-circuit early; their content is path-keyed and
    /// can't be deduped anyway.
    pub(in crate::vfs::host) fn notify_inode(&self, mount_id: u32, dev: u64, ino: u64) {
        if dev == 0 && ino == 0 {
            return;
        }
        let nodeids = self.id_table.nodeids_for_inode(mount_id, dev, ino);
        if nodeids.len() < 2 {
            return;
        }
        // Snapshot the senders (cheap clone — UnboundedSender is just
        // an Arc inside) so we don't hold the registry lock across
        // sends.
        let targets: Vec<_> = {
            let guard = self.notifiers.read();
            guard
                .iter()
                .filter(|e| e.mount_id.is_none_or(|m| m == mount_id))
                .map(|e| e.tx.clone())
                .collect()
        };
        for nodeid in nodeids {
            for tx in &targets {
                let _ = tx.send(Inval::Inode { nodeid, off: 0, len: 0 });
            }
        }
    }

    /// Fire `FUSE_NOTIFY_INVAL_ENTRY` so the guest kernel drops any
    /// cached dentry for `(parent_nodeid, name)`. Used by rename to
    /// evict the source-side dentry.
    pub(in crate::vfs::host) fn notify_entry(&self, mount_id: u32, parent_nodeid: u64, name: &str) {
        let targets: Vec<_> = {
            let guard = self.notifiers.read();
            guard
                .iter()
                .filter(|e| e.mount_id.is_none_or(|m| m == mount_id))
                .map(|e| e.tx.clone())
                .collect()
        };
        for tx in targets {
            let _ = tx.send(Inval::Entry {
                parent_nodeid,
                name: name.to_string(),
            });
        }
    }

    // ---- Watcher-callable accessors --------------------------------
    //
    // The watcher module lives in a sibling submodule but logically
    // belongs to FuseHost. Expose just the operations it needs (one
    // by_path lookup + two raw frame pushes) rather than widening
    // `pub(super)` on a bunch of internals.

    pub(in crate::vfs::host) fn id_table_find_path(&self, mount_id: u32, path: &Path) -> Option<u64> {
        self.id_table.find_path_nodeid(mount_id, path)
    }

    /// Push a single `Inval::Inode { nodeid }` to every notifier bound
    /// to (or wildcard over) `mount_id`. Skips the alias-count check
    /// that `notify_inode` enforces — the watcher already knows the
    /// exact nodeid that changed.
    pub(in crate::vfs::host) fn notify_inode_external(&self, mount_id: u32, nodeid: u64) {
        let targets: Vec<_> = {
            let guard = self.notifiers.read();
            guard
                .iter()
                .filter(|e| e.mount_id.is_none_or(|m| m == mount_id))
                .map(|e| e.tx.clone())
                .collect()
        };
        for tx in targets {
            // Two-shot invalidation: off = -1 drops the cached size +
            // attrs (required so the next read sees the new EOF), and
            // off = 0, len = 0 drops the page cache range so the read
            // actually fetches fresh bytes. Both messages also flush
            // attrs, so order is not critical.
            let _ = tx.send(Inval::Inode {
                nodeid,
                off: -1,
                len: 0,
            });
            let _ = tx.send(Inval::Inode { nodeid, off: 0, len: 0 });
        }
    }

    /// Same wire-level effect as [`Self::notify_entry`]; exposed under
    /// a distinct name purely to make the call sites in `watcher.rs`
    /// self-documenting.
    pub(in crate::vfs::host) fn notify_entry_external(&self, mount_id: u32, parent_nodeid: u64, name: &str) {
        self.notify_entry(mount_id, parent_nodeid, name);
    }
}

// ---------------------------------------------------------------------------
// Tiny RwLock shim to avoid adding parking_lot just for one type.
// ---------------------------------------------------------------------------
mod parking_lot_compat {
    use std::sync::{RwLock as StdRwLock, RwLockReadGuard, RwLockWriteGuard};

    pub struct RwLock<T>(StdRwLock<T>);

    impl<T> RwLock<T> {
        pub fn new(t: T) -> Self {
            Self(StdRwLock::new(t))
        }
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            self.0.read().unwrap_or_else(|e| {
                tracing::warn!("rwlock poisoned, recovering: {e}");
                e.into_inner()
            })
        }
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            self.0.write().unwrap_or_else(|e| {
                tracing::warn!("rwlock poisoned, recovering: {e}");
                e.into_inner()
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs_impls::{LocalDirVfs, MemFsVfs};
    use crate::vfs_protocol::{Errno, PROTOCOL_VERSION};
    use std::sync::Arc;
    use std::time::Duration;

    fn host_with_mount(backend: SharedVfsBackend, ro: bool) -> (Arc<FuseHost>, u32) {
        let host = Arc::new(FuseHost::new());
        let mid = host.register_mount("test", backend, ro);
        (host, mid)
    }

    #[tokio::test]
    async fn lookup_then_getattr() {
        let mem = MemFsVfs::arc();
        // seed
        let any = mem.clone();
        any.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        any.as_put()
            .unwrap()
            .put(Path::new("/hello.txt"), b"hi".to_vec())
            .await
            .unwrap();

        let (host, mid) = host_with_mount(mem, false);
        let r = host.clone().op_lookup(mid, 1, "hello.txt").await;
        let nodeid = match r {
            Res::Entry(e) => {
                assert_eq!(e.attr.size, 2);
                assert_eq!(e.attr.kind, NodeKind::File);
                e.nodeid
            }
            other => panic!("{:?}", other),
        };
        let r2 = host.op_getattr(mid, nodeid).await;
        assert!(matches!(r2, Res::Attr(_)));
    }

    #[tokio::test]
    async fn opendir_readdir_releasedir() {
        let mem = MemFsVfs::arc();
        mem.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        mem.as_put().unwrap().put(Path::new("/a"), b"x".to_vec()).await.unwrap();

        let (host, mid) = host_with_mount(mem, false);
        let fh = match host.clone().op_opendir(mid, 1).await {
            Res::OpenOk { fh } => fh,
            other => panic!("{:?}", other),
        };
        let entries = match host.op_readdir(fh, 0).await {
            Res::DirEntries(v) => v,
            other => panic!("{:?}", other),
        };
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name, ".");
        assert_eq!(entries[0].offset, 1);
        assert_eq!(entries[1].name, "..");
        assert_eq!(entries[1].offset, 2);
        let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"d".to_string()));
        assert!(names.contains(&"a".to_string()));

        let _ = host.id_table.take_fh(fh);
    }

    #[tokio::test]
    async fn write_through_release_drains_to_backend() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalDirVfs::arc(dir.path());
        let (host, mid) = host_with_mount(local, false);

        // create empty file via put
        host.get_mount(mid)
            .unwrap()
            .backend
            .as_put()
            .unwrap()
            .put(Path::new("/f"), Vec::new())
            .await
            .unwrap();

        // lookup → open(O_WRONLY) → write → release
        let nodeid = match host.clone().op_lookup(mid, 1, "f").await {
            Res::Entry(e) => e.nodeid,
            other => panic!("{:?}", other),
        };
        let fh = match host.clone().op_open(mid, nodeid, 0o1).await {
            Res::OpenOk { fh } => fh,
            other => panic!("{:?}", other),
        };
        match host.op_write(fh, 0, b"HELLO".to_vec()).await {
            Res::Written { size } => assert_eq!(size, 5),
            other => panic!("{:?}", other),
        }
        match host.op_release(fh).await {
            Res::Ok => {}
            other => panic!("{:?}", other),
        }

        // verify on host
        let bytes = std::fs::read(dir.path().join("f")).unwrap();
        assert_eq!(bytes, b"HELLO");
    }

    #[tokio::test]
    async fn open_for_write_on_readonly_mount_returns_erofs() {
        let mem = MemFsVfs::arc();
        mem.as_put().unwrap().put(Path::new("/f"), b"x".to_vec()).await.unwrap();
        let (host, mid) = host_with_mount(mem, true);
        let nodeid = match host.clone().op_lookup(mid, 1, "f").await {
            Res::Entry(e) => e.nodeid,
            other => panic!("{:?}", other),
        };
        match host.op_open(mid, nodeid, 0o1).await {
            Res::Error(we) => {
                assert!(
                    we.errno == Errno::Eacces as i32 || we.errno == Errno::Erofs as i32,
                    "got errno {}",
                    we.errno
                );
            }
            other => panic!("{:?}", other),
        }
    }

    #[tokio::test]
    async fn mkdir_unlink_rmdir_rename() {
        let mem = MemFsVfs::arc();
        let (host, mid) = host_with_mount(mem, false);

        // mkdir /d
        assert!(matches!(host.op_mkdir(mid, 1, "d", 0o755).await, Res::Entry(_)));

        // populate /d/x via backend
        host.get_mount(mid)
            .unwrap()
            .backend
            .as_put()
            .unwrap()
            .put(Path::new("/d/x"), b"x".to_vec())
            .await
            .unwrap();

        // rmdir on non-empty must fail
        assert!(matches!(host.op_rmdir(mid, 1, "d").await, Res::Error(_)));

        // unlink looks up child of nodeid 1, so unlinking "d" hits delete_file
        // which returns IsDir.
        match host.op_unlink(mid, 1, "d").await {
            Res::Error(we) => assert_eq!(we.errno, Errno::Eisdir as i32),
            other => panic!("{:?}", other),
        }

        // lookup d, then unlink x via that parent nodeid
        let d_nodeid = match host.clone().op_lookup(mid, 1, "d").await {
            Res::Entry(e) => e.nodeid,
            other => panic!("{:?}", other),
        };
        match host.op_unlink(mid, d_nodeid, "x").await {
            Res::Ok => {}
            other => panic!("{:?}", other),
        }

        // now rmdir succeeds
        match host.op_rmdir(mid, 1, "d").await {
            Res::Ok => {}
            other => panic!("{:?}", other),
        }
    }

    #[tokio::test]
    async fn full_handshake_via_pipe() {
        let mem = MemFsVfs::arc();
        let (host, _mid) = host_with_mount(mem, false);

        let (a, b) = tokio::io::duplex(8192);
        // server side
        let server = tokio::spawn({
            let host = host.clone();
            async move { host.serve(b).await }
        });

        // client side
        let (mut ar, mut aw) = tokio::io::split(a);
        write_frame(
            &mut aw,
            &Frame::Hello {
                proto_version: PROTOCOL_VERSION,
                max_inflight: 16,
                client_name: "test".into(),
                mount_name: None,
            },
        )
        .await
        .unwrap();
        let ack = read_frame(&mut ar).await.unwrap().unwrap();
        assert!(matches!(ack, Frame::HelloAck { .. }));

        write_frame(
            &mut aw,
            &Frame::Request {
                req_id: 1,
                mount_id: 0,
                op: Req::GetAttr { nodeid: 1 },
            },
        )
        .await
        .unwrap();
        let resp = read_frame(&mut ar).await.unwrap().unwrap();
        match resp {
            Frame::Response { req_id, result } => {
                assert_eq!(req_id, 1);
                assert!(matches!(result, Res::Attr(_)));
            }
            other => panic!("{:?}", other),
        }
        drop(aw);
        drop(ar);
        let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
    }
}
