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

pub mod id_table;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;

use crate::vfs_backend::{SharedVfsBackend, VfsError, VfsFileInfo, VfsResult};
use crate::vfs_protocol::wire::{read_frame, write_frame};
use crate::vfs_protocol::{
    AttrOut, DirEntry as WireDirEntry, DirEntryPlus as WireDirEntryPlus, EntryOut, Frame, NodeKind, Req, Res,
    StatfsOut, errno_for,
};
use id_table::{FhEntry, IdTable, StagingFile};

/// Lightweight clone of [`VfsFileInfo`] used inside `FhEntry::Dir`
/// snapshots. Carries enough metadata for both `ReadDir` (just kind)
/// and `ReadDirPlus` (full attrs) without re-stat'ing.
#[derive(Debug, Clone)]
pub struct DirSnapshot {
    pub kind: NodeKind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
}

// ---------------------------------------------------------------------------
// FuseHost
// ---------------------------------------------------------------------------

/// One [`FuseHost`] per sandbox session: a registry of mounts plus the
/// per-connection serve loop.
pub struct FuseHost {
    mounts: parking_lot_compat::RwLock<Vec<Option<MountEntry>>>,
    id_table: IdTable,
}

#[derive(Clone)]
struct MountEntry {
    name: String,
    backend: SharedVfsBackend,
    read_only: bool,
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
        }
    }

    /// Register a mount and return its `mount_id`. The id is stable for
    /// the lifetime of the slot; [`Self::remove_mount`] frees it for
    /// reuse.
    pub fn register_mount(&self, name: impl Into<String>, backend: SharedVfsBackend, read_only: bool) -> u32 {
        let mut mounts = self.mounts.write();
        // Prefer reusing a free slot.
        for (i, slot) in mounts.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(MountEntry {
                    name: name.into(),
                    backend,
                    read_only,
                });
                return i as u32;
            }
        }
        mounts.push(Some(MountEntry {
            name: name.into(),
            backend,
            read_only,
        }));
        (mounts.len() - 1) as u32
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

    fn get_mount(&self, mount_id: u32) -> Option<MountEntry> {
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
        let max_inflight = {
            let mut guard = tx.lock().await;
            match crate::vfs_protocol::handshake::server_handshake(&mut rx, &mut *guard, |n| self.mount_id_by_name(n))
                .await?
            {
                Some(mi) => mi,
                None => return Ok(()),
            }
        };

        let _ = max_inflight; // backpressure not enforced server-side yet

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
                mode: _,
            } => self.op_mkdir(mount_id, parent_nodeid, &name).await,
            Req::Create {
                parent_nodeid,
                name,
                mode: _,
            } => self.op_create(mount_id, parent_nodeid, &name).await,
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
        }
    }

    // -----------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------

    /// Translate `(mount_id, nodeid)` to a vfs-relative path. `nodeid==1`
    /// is always the export root `/`.
    fn resolve_path(&self, mount_id: u32, nodeid: u64) -> Result<PathBuf, Res> {
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
        Ok(n.path)
    }

    fn child_path(parent: &Path, name: &str) -> PathBuf {
        if parent == Path::new("/") {
            PathBuf::from(format!("/{name}"))
        } else {
            let mut p = parent.to_path_buf();
            p.push(name);
            p
        }
    }

    // -----------------------------------------------------------------
    // Op handlers
    // -----------------------------------------------------------------

    async fn op_lookup(self: Arc<Self>, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let path = Self::child_path(&parent, name);
        match mount.backend.stat(&path).await {
            Ok(info) => {
                let (nodeid, _) = self.id_table.intern(mount_id, path);
                Res::Entry(EntryOut {
                    nodeid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_getattr(&self, mount_id: u32, nodeid: u64) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        match mount.backend.stat(&path).await {
            Ok(info) => Res::Attr(attr_from(&info)),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_setattr(
        &self,
        mount_id: u32,
        nodeid: u64,
        _mode: Option<u32>,
        size: Option<u64>,
        _atime: Option<i64>,
        _mtime: Option<i64>,
    ) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }

        // Only `size` truncation is honoured for now (matches what most
        // callers do via `O_TRUNC` at open time).
        if let Some(sz) = size {
            // Try resolve_local + std::fs truncate; otherwise read-modify-put.
            if let Some(resolver) = mount.backend.as_resolve_local() {
                if let Some(host_path) = resolver.resolve_real_path(&path) {
                    if let Err(e) = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&host_path)
                        .and_then(|f| f.set_len(sz))
                    {
                        return Res::Error(errno_for(&VfsError::from(e)));
                    }
                } else if let Some(put) = mount.backend.as_put() {
                    let data = match mount.backend.read_bytes(&path, 0, Some(sz)).await {
                        Ok(d) => d,
                        Err(e) => return Res::Error(errno_for(&e)),
                    };
                    let mut data = data;
                    data.resize(sz as usize, 0);
                    if let Err(e) = put.put(&path, data).await {
                        return Res::Error(errno_for(&e));
                    }
                } else {
                    return Res::Error(errno_for(&VfsError::NotImplemented("truncate".into())));
                }
            } else if let Some(put) = mount.backend.as_put() {
                let data = match mount.backend.read_bytes(&path, 0, Some(sz)).await {
                    Ok(d) => d,
                    Err(e) => return Res::Error(errno_for(&e)),
                };
                let mut data = data;
                data.resize(sz as usize, 0);
                if let Err(e) = put.put(&path, data).await {
                    return Res::Error(errno_for(&e));
                }
            } else {
                return Res::Error(errno_for(&VfsError::NotImplemented("truncate".into())));
            }
        }

        // Re-stat for fresh attrs.
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        match mount.backend.stat(&path).await {
            Ok(info) => Res::Attr(attr_from(&info)),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_opendir(self: Arc<Self>, mount_id: u32, nodeid: u64) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let entries = match mount.backend.list(&path).await {
            Ok(e) => e,
            Err(e) => return Res::Error(errno_for(&e)),
        };
        let snapshot: Vec<(String, DirSnapshot)> = entries
            .into_iter()
            .map(|info| {
                let attr = attr_from(&info);
                let snap = DirSnapshot {
                    kind: attr.kind,
                    size: attr.size,
                    mode: attr.mode,
                    mtime: attr.mtime,
                };
                (info.name, snap)
            })
            .collect();
        let fh = self.id_table.alloc_fh(FhEntry::Dir {
            mount_id,
            nodeid,
            entries: snapshot,
        });
        Res::OpenOk { fh }
    }

    async fn op_readdir(&self, fh: u64, offset: u64) -> Res {
        // Snapshot under the lock, then build the response.
        let snap = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::Dir {
                mount_id,
                nodeid,
                entries,
            } => Some((*mount_id, *nodeid, entries.clone())),
            _ => None,
        });
        let Some(Some((mount_id, dir_nodeid, entries))) = snap else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        let dir_path = match self.resolve_path(mount_id, dir_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let parent_nodeid = if dir_path == Path::new("/") {
            1
        } else {
            let parent_path = dir_path.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
            let (nodeid, _) = self.id_table.intern_peek(mount_id, parent_path);
            nodeid
        };

        let off = offset as usize;
        let mut out = Vec::new();
        if off == 0 {
            out.push(WireDirEntry {
                nodeid: dir_nodeid,
                offset: 1,
                kind: NodeKind::Dir,
                name: ".".into(),
            });
        }
        if off <= 1 {
            out.push(WireDirEntry {
                nodeid: parent_nodeid,
                offset: 2,
                kind: NodeKind::Dir,
                name: "..".into(),
            });
        }
        for (i, (name, snap)) in entries.into_iter().enumerate().skip(off.saturating_sub(2)) {
            let child = Self::child_path(&dir_path, &name);
            let (nodeid, _) = self.id_table.intern_peek(mount_id, child);
            out.push(WireDirEntry {
                nodeid,
                offset: (i + 3) as u64,
                kind: snap.kind,
                name,
            });
        }
        Res::DirEntries(out)
    }

    /// FUSE READDIRPLUS: same iteration as [`op_readdir`](Self::op_readdir)
    /// but each entry carries full attrs and bumps the lookup count
    /// (kernel will [`Forget`](Req::Forget) when evicting from cache).
    async fn op_readdirplus(&self, fh: u64, offset: u64) -> Res {
        let snap = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::Dir {
                mount_id,
                nodeid,
                entries,
            } => Some((*mount_id, *nodeid, entries.clone())),
            _ => None,
        });
        let Some(Some((mount_id, dir_nodeid, entries))) = snap else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        let dir_path = match self.resolve_path(mount_id, dir_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let parent_nodeid = if dir_path == Path::new("/") {
            1
        } else {
            let parent_path = dir_path.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
            let (nodeid, _) = self.id_table.intern_peek(mount_id, parent_path);
            nodeid
        };

        let off = offset as usize;
        let mut out = Vec::new();
        let generation = self.id_table.generation();

        // "." and ".." get nodeid=0/0 attrs from a stat-on-demand cost we
        // skip — the kernel only uses these for completeness, not for
        // attr caching. We still must include them with valid attrs or
        // some kernels reject the entry. Use a synthetic dir attr.
        let synthetic_dir_attr = AttrOut {
            size: 0,
            blocks: 0,
            mtime: 0,
            mode: 0o755,
            nlink: 2,
            #[cfg(target_os = "linux")]
            uid: unsafe { libc::getuid() },
            #[cfg(target_os = "linux")]
            gid: unsafe { libc::getgid() },
            #[cfg(not(target_os = "linux"))]
            uid: 0,
            #[cfg(not(target_os = "linux"))]
            gid: 0,
            kind: NodeKind::Dir,
        };
        if off == 0 {
            out.push(WireDirEntryPlus {
                offset: 1,
                name: ".".into(),
                entry: EntryOut {
                    nodeid: dir_nodeid,
                    generation,
                    attr: synthetic_dir_attr.clone(),
                },
            });
        }
        if off <= 1 {
            out.push(WireDirEntryPlus {
                offset: 2,
                name: "..".into(),
                entry: EntryOut {
                    nodeid: parent_nodeid,
                    generation,
                    attr: synthetic_dir_attr,
                },
            });
        }

        #[cfg(target_os = "linux")]
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        #[cfg(not(target_os = "linux"))]
        let (uid, gid) = (0u32, 0u32);

        for (i, (name, snap)) in entries.into_iter().enumerate().skip(off.saturating_sub(2)) {
            let child = Self::child_path(&dir_path, &name);
            // intern() bumps lookup count — required for READDIRPLUS so
            // the kernel's Forget pairs balance out.
            let (nodeid, _) = self.id_table.intern(mount_id, child);
            out.push(WireDirEntryPlus {
                offset: (i + 3) as u64,
                name,
                entry: EntryOut {
                    nodeid,
                    generation,
                    attr: AttrOut {
                        size: snap.size,
                        blocks: snap.size.div_ceil(512),
                        mtime: snap.mtime,
                        mode: snap.mode,
                        nlink: 1,
                        uid,
                        gid,
                        kind: snap.kind,
                    },
                },
            });
        }
        Res::DirEntriesPlus(out)
    }

    async fn op_open(self: Arc<Self>, mount_id: u32, nodeid: u64, flags: u32) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };

        const O_ACCMODE: u32 = 0o3;
        const O_WRONLY: u32 = 0o1;
        const O_RDWR: u32 = 0o2;
        const O_TRUNC: u32 = 0o1000;
        let access = flags & O_ACCMODE;
        let needs_write = access == O_WRONLY || access == O_RDWR;

        if needs_write {
            if mount.read_only {
                return Res::Error(errno_for(&VfsError::PermissionDenied));
            }
            if mount.backend.as_put().is_none()
                && mount.backend.as_put_stream().is_none()
                && mount.backend.as_resolve_local().is_none()
            {
                return Res::Error(crate::vfs_protocol::WireError {
                    errno: crate::vfs_protocol::Errno::Erofs as i32,
                    message: "backend has no write capability".into(),
                });
            }
        }

        // Fastpath: backend exposes a real local path → open the host
        // file once and let op_read/op_write do direct pread/pwrite.
        let host_file = if let Some(resolver) = mount.backend.as_resolve_local() {
            if let Some(real) = resolver.resolve_real_path(&path) {
                let mut opts = std::fs::OpenOptions::new();
                opts.read(true);
                if needs_write {
                    opts.write(true);
                    if (flags & O_TRUNC) != 0 {
                        opts.truncate(true);
                    }
                }
                match tokio::task::spawn_blocking(move || opts.open(&real)).await {
                    Ok(Ok(f)) => Some(Arc::new(f)),
                    Ok(Err(e)) => return Res::Error(errno_for(&VfsError::from(e))),
                    Err(e) => return Res::Error(errno_for(&VfsError::Io(e.to_string()))),
                }
            } else {
                None
            }
        } else {
            None
        };

        // Slow path: just verify the file exists.
        if host_file.is_none()
            && !needs_write
            && let Err(e) = mount.backend.stat(&path).await
        {
            return Res::Error(errno_for(&e));
        }

        let fh = self.id_table.alloc_fh(FhEntry::File {
            mount_id,
            nodeid,
            flags,
            staging: None,
            host_file,
        });
        Res::OpenOk { fh }
    }

    async fn op_read(&self, fh: u64, offset: u64, size: u32) -> Res {
        let info = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File {
                mount_id,
                nodeid,
                host_file,
                ..
            } => Some((*mount_id, *nodeid, host_file.clone())),
            _ => None,
        });
        let Some(Some((mount_id, nodeid, host_file))) = info else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };

        // Fastpath: pread directly from the local host file.
        if let Some(file) = host_file {
            let want = size as usize;
            let res = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileExt;
                    let mut buf = vec![0u8; want];
                    let mut filled = 0;
                    while filled < want {
                        match file.read_at(&mut buf[filled..], offset + filled as u64)? {
                            0 => break,
                            n => filled += n,
                        }
                    }
                    buf.truncate(filled);
                    Ok(buf)
                }
                #[cfg(not(unix))]
                {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = (*file).try_clone()?;
                    f.seek(SeekFrom::Start(offset))?;
                    let mut buf = Vec::with_capacity(want);
                    f.take(want as u64).read_to_end(&mut buf)?;
                    Ok(buf)
                }
            })
            .await;
            return match res {
                Ok(Ok(bytes)) => Res::Bytes(bytes),
                Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
                Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
            };
        }

        // Slow path: backend does its own thing.
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        match mount.backend.read_bytes(&path, offset, Some(size as u64)).await {
            Ok(b) => Res::Bytes(b),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_write(&self, fh: u64, offset: u64, data: Vec<u8>) -> Res {
        let written = data.len() as u32;

        // Fastpath: pwrite directly to the local host file.
        let host_file = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File { host_file, .. } => host_file.clone(),
            _ => None,
        });
        if let Some(Some(file)) = host_file {
            let res = tokio::task::spawn_blocking(move || -> io::Result<()> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileExt;
                    let mut written_off = 0;
                    while written_off < data.len() {
                        match file.write_at(&data[written_off..], offset + written_off as u64)? {
                            0 => {
                                return Err(io::Error::new(io::ErrorKind::WriteZero, "pwrite returned 0"));
                            }
                            n => written_off += n,
                        }
                    }
                    Ok(())
                }
                #[cfg(not(unix))]
                {
                    use std::io::{Seek, SeekFrom, Write as _};
                    let mut f = (*file).try_clone()?;
                    f.seek(SeekFrom::Start(offset))?;
                    f.write_all(&data)?;
                    Ok(())
                }
            })
            .await;
            return match res {
                Ok(Ok(())) => Res::Written { size: written },
                Ok(Err(e)) => Res::Error(errno_for(&VfsError::from(e))),
                Err(e) => Res::Error(errno_for(&VfsError::Io(e.to_string()))),
            };
        }

        // Slow path: stage into a tempfile, drain on Flush/Release.
        use std::io::{Seek, SeekFrom, Write as _};

        let staging_path: PathBuf = match self.id_table.with_fh_mut(fh, |entry| -> VfsResult<PathBuf> {
            let FhEntry::File { staging, .. } = entry else {
                return Err(VfsError::InvalidArgument("bad fh".into()));
            };
            if staging.is_none() {
                let tmp = tempfile::Builder::new()
                    .prefix("tokimo-fuse-")
                    .tempfile()
                    .map_err(VfsError::from)?;
                let (file, path) = tmp.keep().map_err(|e| VfsError::Io(e.to_string()))?;
                *staging = Some(StagingFile {
                    path: path.clone(),
                    file,
                    max_offset: 0,
                    dirty: true,
                });
                Ok(path)
            } else {
                Ok(staging.as_ref().unwrap().path.clone())
            }
        }) {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Res::Error(errno_for(&e)),
            None => return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into()))),
        };

        let res = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).open(&staging_path)?;
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(&data)?;
            Ok(())
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Res::Error(errno_for(&VfsError::from(e))),
            Err(e) => return Res::Error(errno_for(&VfsError::Io(e.to_string()))),
        }

        self.id_table.with_fh_mut(fh, |entry| {
            if let FhEntry::File { staging: Some(s), .. } = entry {
                s.max_offset = s.max_offset.max(offset + written as u64);
                s.dirty = true;
            }
        });

        Res::Written { size: written }
    }

    async fn op_flush(&self, fh: u64) -> Res {
        // Snapshot fh state without taking ownership.
        let fh_state = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File {
                mount_id,
                nodeid,
                staging,
                host_file,
                ..
            } => {
                // Direct-IO fh: nothing to flush; the kernel already
                // pushed bytes into the file via pwrite.
                if host_file.is_some() {
                    return Some((*mount_id, *nodeid, None));
                }
                let staging_info = staging
                    .as_ref()
                    .filter(|s| s.dirty)
                    .map(|s| (s.path.clone(), s.max_offset));
                Some((*mount_id, *nodeid, staging_info))
            }
            _ => None,
        });
        let Some(Some((mount_id, nodeid, staging))) = fh_state else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        let Some((staging_path, size)) = staging else {
            return Res::Ok; // no dirty data
        };

        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };

        if let Err(e) = drain_staging_to_backend(&mount, &path, &staging_path, size).await {
            return Res::Error(errno_for(&e));
        }

        // Mark clean.
        self.id_table.with_fh_mut(fh, |entry| {
            if let FhEntry::File { staging: Some(s), .. } = entry {
                s.dirty = false;
            }
        });

        Res::Ok
    }

    async fn op_release(&self, fh: u64) -> Res {
        let Some(entry) = self.id_table.take_fh(fh) else {
            return Res::Ok; // tolerate double-release
        };
        let FhEntry::File {
            mount_id,
            nodeid,
            staging,
            host_file,
            ..
        } = entry
        else {
            return Res::Ok;
        };
        // Direct-IO fh: just drop the file; bytes are already on disk.
        if host_file.is_some() {
            drop(host_file);
            return Res::Ok;
        }
        if let Some(s) = staging {
            if s.dirty {
                let path = match self.resolve_path(mount_id, nodeid) {
                    Ok(p) => p,
                    Err(r) => return r,
                };
                let Some(mount) = self.get_mount(mount_id) else {
                    return Res::Error(errno_for(&VfsError::NotFound));
                };
                if let Err(e) = drain_staging_to_backend(&mount, &path, &s.path, s.max_offset).await {
                    let _ = std::fs::remove_file(&s.path);
                    return Res::Error(errno_for(&e));
                }
            }
            let _ = std::fs::remove_file(&s.path);
        }
        Res::Ok
    }

    async fn op_mkdir(&self, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(mk) = mount.backend.as_mkdir() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("mkdir".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = mk.mkdir(&path).await {
            eprintln!("[vfs_host] op_mkdir host-side FAILED: parent={parent:?} name={name:?} err={e:?}");
            return Res::Error(errno_for(&e));
        }
        eprintln!("[vfs_host] op_mkdir host-side OK: path={path:?}");
        match mount.backend.stat(&path).await {
            Ok(info) => {
                let (nodeid, _) = self.id_table.intern(mount_id, path);
                Res::Entry(EntryOut {
                    nodeid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_create(&self, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(put) = mount.backend.as_put() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("create".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = put.put(&path, Vec::new()).await {
            return Res::Error(errno_for(&e));
        }
        match mount.backend.stat(&path).await {
            Ok(info) => {
                let (nodeid, _) = self.id_table.intern(mount_id, path);
                Res::Entry(EntryOut {
                    nodeid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_rmdir(&self, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(d) = mount.backend.as_delete_dir() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("rmdir".into())));
        };
        let path = Self::child_path(&parent, name);
        match d.delete_dir(&path).await {
            Ok(()) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_unlink(&self, mount_id: u32, parent_nodeid: u64, name: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(d) = mount.backend.as_delete_file() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("unlink".into())));
        };
        let path = Self::child_path(&parent, name);
        match d.delete_file(&path).await {
            Ok(()) => Res::Ok,
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_rename(&self, mount_id: u32, old_parent: u64, old_name: &str, new_parent: u64, new_name: &str) -> Res {
        let op = match self.resolve_path(mount_id, old_parent) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let np = match self.resolve_path(mount_id, new_parent) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let from = Self::child_path(&op, old_name);
        let to = Self::child_path(&np, new_name);

        if old_parent == new_parent
            && let Some(r) = mount.backend.as_rename()
        {
            return match r.rename(&from, &to).await {
                Ok(()) => Res::Ok,
                Err(e) => Res::Error(errno_for(&e)),
            };
        }
        if let Some(m) = mount.backend.as_move() {
            // VfsMove takes a target directory + keeps the leaf name; if
            // the user asked for a new leaf name we have to fall back to
            // copy + delete via Rename. Many drivers offer both.
            if old_name == new_name {
                return match m.move_file(&from, &np).await {
                    Ok(()) => Res::Ok,
                    Err(e) => Res::Error(errno_for(&e)),
                };
            }
        }
        if let Some(r) = mount.backend.as_rename() {
            return match r.rename(&from, &to).await {
                Ok(()) => Res::Ok,
                Err(e) => Res::Error(errno_for(&e)),
            };
        }
        Res::Error(errno_for(&VfsError::NotImplemented("rename".into())))
    }

    async fn op_symlink(&self, mount_id: u32, parent_nodeid: u64, name: &str, target: &str) -> Res {
        let parent = match self.resolve_path(mount_id, parent_nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        if mount.read_only {
            return Res::Error(errno_for(&VfsError::PermissionDenied));
        }
        let Some(s) = mount.backend.as_symlink() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("symlink".into())));
        };
        let path = Self::child_path(&parent, name);
        if let Err(e) = s.symlink(target, &path).await {
            return Res::Error(errno_for(&e));
        }
        match mount.backend.stat(&path).await {
            Ok(info) => {
                let (nodeid, _) = self.id_table.intern(mount_id, path);
                Res::Entry(EntryOut {
                    nodeid,
                    generation: self.id_table.generation(),
                    attr: attr_from(&info),
                })
            }
            Err(e) => Res::Error(errno_for(&e)),
        }
    }

    async fn op_readlink(&self, mount_id: u32, nodeid: u64) -> Res {
        let path = match self.resolve_path(mount_id, nodeid) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(mount) = self.get_mount(mount_id) else {
            return Res::Error(errno_for(&VfsError::NotFound));
        };
        let Some(r) = mount.backend.as_readlink() else {
            return Res::Error(errno_for(&VfsError::NotImplemented("readlink".into())));
        };
        match r.readlink(&path).await {
            Ok(target) => Res::Linkname(target),
            Err(e) => Res::Error(errno_for(&e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true for ops that complete in tens of µs without doing real
/// I/O, so it's cheaper to await them inline than to allocate a new
/// tokio task. Heavy ops (Read/Write/ReadDir/ReadDirPlus do bulk
/// transfers or backend list/stat per entry) get spawned so they don't
/// stall the read loop.
fn op_is_cheap(op: &Req) -> bool {
    matches!(
        op,
        Req::Forget { .. }
            | Req::GetAttr { .. }
            | Req::Lookup { .. }
            | Req::Open { .. }
            | Req::OpenDir { .. }
            | Req::Release { .. }
            | Req::ReleaseDir { .. }
            | Req::Flush { .. }
            | Req::Statfs { .. }
    )
}

fn attr_from(info: &VfsFileInfo) -> AttrOut {
    let kind = if info.is_symlink {
        NodeKind::Symlink
    } else if info.is_dir {
        NodeKind::Dir
    } else {
        NodeKind::File
    };
    let mode = info.mode.unwrap_or(match kind {
        NodeKind::Dir => 0o755,
        NodeKind::Symlink => 0o777,
        NodeKind::File => 0o644,
    });
    let mtime = info
        .modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // On Linux the FuseHost runs in-process (bwrap path) so the calling
    // UID matches the host user — return real uid/gid so DefaultPermissions
    // allows writes. On macOS/Windows the FuseHost serves a Linux VM
    // where processes run as root — return 0/0 so root-owned files are
    // writable inside the guest.
    #[cfg(target_os = "linux")]
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    #[cfg(not(target_os = "linux"))]
    let (uid, gid) = (0u32, 0u32);
    AttrOut {
        size: info.size,
        blocks: info.size.div_ceil(512),
        mtime,
        mode,
        nlink: 1,
        uid,
        gid,
        kind,
    }
}

async fn drain_staging_to_backend(mount: &MountEntry, path: &Path, staging_path: &Path, size: u64) -> VfsResult<()> {
    // Prefer streaming if available; otherwise read into memory + put.
    if let Some(stream) = mount.backend.as_put_stream() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let path_cl = staging_path.to_path_buf();
        let total = size;
        let pump = tokio::task::spawn_blocking(move || -> io::Result<()> {
            use std::io::Read;
            let mut f = std::fs::File::open(&path_cl)?;
            let mut remaining = total;
            let mut buf = vec![0u8; 256 * 1024];
            while remaining > 0 {
                let want = remaining.min(buf.len() as u64) as usize;
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    break;
                }
                let chunk = buf[..n].to_vec();
                if tx.blocking_send(chunk).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            Ok(())
        });
        let put_res = stream.put_stream(path, size, rx).await;
        let pump_res = pump.await.map_err(|e| VfsError::Io(e.to_string()))?;
        pump_res.map_err(VfsError::from)?;
        put_res?;
        return Ok(());
    }
    if let Some(p) = mount.backend.as_put() {
        let path_cl = staging_path.to_path_buf();
        let data = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> { std::fs::read(&path_cl) })
            .await
            .map_err(|e| VfsError::Io(e.to_string()))?
            .map_err(VfsError::from)?;
        // Truncate to declared size so over-allocated tempfile doesn't bleed.
        let data = if data.len() as u64 > size {
            data[..size as usize].to_vec()
        } else {
            data
        };
        return p.put(path, data).await;
    }
    Err(VfsError::NotImplemented("backend has no put / put_stream".into()))
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
            self.0.read().unwrap()
        }
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            self.0.write().unwrap()
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
        assert!(matches!(host.op_mkdir(mid, 1, "d").await, Res::Entry(_)));

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
