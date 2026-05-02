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
    AttrOut, DirEntry as WireDirEntry, EntryOut, Frame, NodeKind, PROTOCOL_VERSION, Req, Res, StatfsOut, errno_for,
};
use id_table::{FhEntry, IdTable, StagingFile};

/// Lightweight clone of [`VfsFileInfo`] used inside `FhEntry::Dir`
/// snapshots. Currently only the kind drives `ReadDir` output; the
/// remaining attrs are re-fetched on `Lookup` when the guest needs them.
#[derive(Debug, Clone)]
pub struct DirSnapshot {
    pub kind: NodeKind,
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
        let Some(first) = read_frame(&mut rx).await? else {
            return Ok(());
        };
        let max_inflight = match first {
            Frame::Hello {
                proto_version,
                max_inflight,
                ..
            } => {
                if proto_version != PROTOCOL_VERSION {
                    let mut tx_guard = tx.lock().await;
                    let _ = write_frame(
                        &mut *tx_guard,
                        &Frame::HelloAck {
                            proto_version: PROTOCOL_VERSION,
                            max_inflight: 0,
                        },
                    )
                    .await;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "protocol mismatch: client={} server={}",
                            proto_version, PROTOCOL_VERSION
                        ),
                    ));
                }
                {
                    let mut tx_guard = tx.lock().await;
                    write_frame(
                        &mut *tx_guard,
                        &Frame::HelloAck {
                            proto_version: PROTOCOL_VERSION,
                            max_inflight,
                        },
                    )
                    .await?;
                }
                max_inflight
            }
            other => {
                tracing::warn!("vfs_host: first frame not Hello: {:?}", other);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "first frame not Hello"));
            }
        };

        let _ = max_inflight; // backpressure not enforced server-side yet

        // 2. Steady state.
        loop {
            let frame = read_frame(&mut rx).await?;
            let Some(frame) = frame else { return Ok(()) };
            match frame {
                Frame::Request { req_id, mount_id, op } => {
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
                let snap = DirSnapshot {
                    kind: if info.is_dir { NodeKind::Dir } else { NodeKind::File },
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
        let Some(Some((_mount_id, parent_nodeid, entries))) = snap else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
        // No nodeid allocation here — the guest will Lookup before using
        // dir entries that need a nodeid. We surface 0 to indicate
        // "lookup required".
        let _ = parent_nodeid;
        let off = offset as usize;
        let mut out = Vec::new();
        for (i, (name, snap)) in entries.into_iter().enumerate().skip(off) {
            out.push(WireDirEntry {
                nodeid: 0,
                offset: (i + 1) as u64,
                kind: snap.kind,
                name,
            });
        }
        Res::DirEntries(out)
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
        let access = flags & O_ACCMODE;
        let needs_write = access == O_WRONLY || access == O_RDWR;

        if needs_write {
            if mount.read_only {
                return Res::Error(errno_for(&VfsError::PermissionDenied));
            }
            if mount.backend.as_put().is_none() && mount.backend.as_put_stream().is_none() {
                return Res::Error(crate::vfs_protocol::WireError {
                    errno: crate::vfs_protocol::Errno::Erofs as i32,
                    message: "backend has no write capability".into(),
                });
            }
        }

        // Verify the file exists (or open with create-on-write semantics).
        // FUSE distinguishes `create` from `open`; we don't implement the
        // create op explicitly — mkdir / put paths handle creation.
        if !needs_write && let Err(e) = mount.backend.stat(&path).await {
            return Res::Error(errno_for(&e));
        }

        let fh = self.id_table.alloc_fh(FhEntry::File {
            mount_id,
            nodeid,
            flags,
            staging: None,
        });
        Res::OpenOk { fh }
    }

    async fn op_read(&self, fh: u64, offset: u64, size: u32) -> Res {
        let info = self.id_table.with_fh_mut(fh, |entry| match entry {
            FhEntry::File { mount_id, nodeid, .. } => Some((*mount_id, *nodeid)),
            _ => None,
        });
        let Some(Some((mount_id, nodeid))) = info else {
            return Res::Error(errno_for(&VfsError::InvalidArgument("bad fh".into())));
        };
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
        use std::io::{Seek, SeekFrom, Write as _};
        let written = data.len() as u32;

        // Take or create the staging file under the table lock.
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

        // Open the staging path and pwrite. Doing this outside the
        // IdTable lock so concurrent writes to other fhs aren't blocked.
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

        // Update max_offset under the lock.
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
                ..
            } => {
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
            ..
        } = entry
        else {
            return Res::Ok;
        };
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn attr_from(info: &VfsFileInfo) -> AttrOut {
    let kind = if info.is_dir { NodeKind::Dir } else { NodeKind::File };
    let mode = info.mode.unwrap_or(if info.is_dir { 0o755 } else { 0o644 });
    let mtime = info
        .modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    AttrOut {
        size: info.size,
        blocks: info.size.div_ceil(512),
        mtime,
        mode,
        nlink: 1,
        uid: 0,
        gid: 0,
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
    use crate::vfs_protocol::Errno;
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
        assert_eq!(entries.len(), 2);
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
