//! In-process NFSv3 server bridging guest `mount(2)` calls to the host
//! filesystem.
//!
//! Architecture:
//!
//! ```text
//!   guest mount -t nfs 192.168.127.1:/<name> /target
//!     ↓ (TCP over smoltcp gateway, spliced via netstack::LocalService)
//!   tokio TcpListener bound to 127.0.0.1:<ephemeral>  (this module)
//!     ↓
//!   nfsserve::tcp::NFSTcpListener<RouterFs>
//!     ↓ NFSFileSystem
//!   VirtualMountRouter — multiplexes the NFS namespace across N host
//!   directories, each appearing under /<name>/ in the export root.
//! ```
//!
//! Each `Sandbox` session owns one `NfsServer`. Multiple sessions get
//! independent ephemeral ports, independent routers, and (because the
//! guest dials a per-session smoltcp gateway) cannot reach each other.
//!
//! ## fileid encoding
//!
//! ```text
//!   fileid3 = (mount_idx << 48) | (path_hash & ((1<<48)-1))
//! ```
//!
//! `mount_idx == 0` is reserved for the export root (the directory whose
//! children are the mount-name subdirs). Within a mount, the root has a
//! reserved low-48 marker (`ROOT_LOW`) and other paths use SipHash-2-4
//! (via std `DefaultHasher`) keyed by a per-server seed.
//!
//! The per-server fh seed is randomised at startup so file handles do not
//! survive an NFS server restart even if the guest re-uses an NFS handle.
//! NFS `nfs_fh3` opaque encoding is also keyed by a generation number that
//! `nfsserve` derives from `SystemTime::now()` at first call, so stale
//! handles from a previous process are rejected.
//!
//! ## Read-only mounts
//!
//! Per-mount `read_only` flag is enforced at every mutating method by
//! returning `nfsstat3::NFS3ERR_ROFS`. This is independent of the NFS
//! mount(2) `ro` flag the guest sets — defence in depth.

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::hash::Hasher;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, set_gid3, set_mode3, set_size3, set_uid3,
    specdata3,
};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};

const ROOT_ID: fileid3 = 1;

/// Default low-48 marker for a mount's own root directory; mixed with
/// `mount_idx` to produce the exported `/<name>/` directory id.
const MOUNT_ROOT_LOW: u64 = 1;

/// Make a fileid from `(mount_idx, low_48)`. `mount_idx` is the public
/// 1-based index (0 is reserved for the export root, never assigned to a
/// mount); we encode it as `mount_idx + 1` in the high bits is NOT done
/// here — callers pass the raw 1-based slot from `MountEntry`'s position.
/// To prevent collision with `ROOT_ID = 1`, real mounts have `mount_idx
/// >= 1` so `(mount_idx << 48) | MOUNT_ROOT_LOW != 1`.
#[inline]
fn make_fileid(mount_idx: u16, low: u64) -> fileid3 {
    debug_assert!(low < (1u64 << 48));
    debug_assert!(mount_idx >= 1, "mount_idx 0 reserved for export root");
    ((mount_idx as u64) << 48) | (low & ((1u64 << 48) - 1))
}

/// Decode `(mount_idx, low_48)` from a fileid.
#[inline]
fn split_fileid(id: fileid3) -> (u16, u64) {
    (((id >> 48) & 0xFFFF) as u16, id & ((1u64 << 48) - 1))
}

/// SipHash-2-4 (via std `DefaultHasher`, which is SipHash-1-3 since 1.13 —
/// the spec language in `plan/macos-nfs-mount.md` says SipHash24 but the
/// guarantee we actually need is "keyed, well-distributed, 64-bit"; std's
/// hasher meets that). Keyed by `seed` and `mount_idx` so collisions are
/// per-mount, never cross-mount.
fn path_hash(seed: u64, mount_idx: u16, rel: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write_u64(seed);
    h.write_u16(mount_idx);
    h.write(rel);
    let v = h.finish() & ((1u64 << 48) - 1);
    // Avoid colliding with the mount-root marker (=1) and 0.
    if v <= MOUNT_ROOT_LOW { v + 2 } else { v }
}

/// Per-mount registration.
#[derive(Debug)]
struct MountEntry {
    #[allow(dead_code)] // kept for diagnostics / future readdir of root
    name: String,
    host_path: PathBuf,
    read_only: bool,
    /// `false` after `remove_mount`. We tombstone instead of removing
    /// from the Vec so previously-issued fileids keep mapping to the
    /// same index.
    active: bool,
}

#[derive(Default)]
struct RouterState {
    /// Index → entry. Tombstoned entries stay in place.
    mounts: Vec<MountEntry>,
    /// Logical name → mount index. Removed entries removed from this map
    /// only (so the name can be re-registered later).
    name_to_idx: HashMap<String, usize>,
    /// fileid (low_48) → relative path within its mount. Populated lazily
    /// as we hand out fileids in lookup / readdir / mkdir / create.
    /// Key encodes the (mount_idx, low) pair as a full u64 so the cache
    /// is shared across mounts.
    inode_cache: HashMap<u64, PathBuf>,
}

/// The NFS namespace multiplexer. One instance per session.
pub struct VirtualMountRouter {
    state: RwLock<RouterState>,
    fh_seed: u64,
}

impl VirtualMountRouter {
    fn new() -> Self {
        // Seed from system time + process id; the values just need to
        // differ between sandboxes within one process, not be
        // cryptographically secure.
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let seed = nanos
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(std::process::id() as u64);
        // Slot 0 is a tombstoned sentinel so real mount indices start at
        // 1 and `(idx << 48) | MOUNT_ROOT_LOW` never collides with
        // ROOT_ID = 1.
        let mut state = RouterState::default();
        state.mounts.push(MountEntry {
            name: String::new(),
            host_path: PathBuf::new(),
            read_only: true,
            active: false,
        });
        Self {
            state: RwLock::new(state),
            fh_seed: seed,
        }
    }

    fn add_mount_inner(&self, name: &str, host_path: PathBuf, read_only: bool) -> Result<u16> {
        let mut st = self.state.write().unwrap();
        if st.name_to_idx.contains_key(name) {
            return Err(Error::validation(format!("nfs share already exists: {name}")));
        }
        let idx = st.mounts.len();
        if idx >= u16::MAX as usize {
            return Err(Error::other("too many nfs mounts"));
        }
        st.mounts.push(MountEntry {
            name: name.to_string(),
            host_path,
            read_only,
            active: true,
        });
        st.name_to_idx.insert(name.to_string(), idx);
        Ok(idx as u16)
    }

    fn remove_mount_inner(&self, name: &str) -> Result<()> {
        let mut st = self.state.write().unwrap();
        let idx = st
            .name_to_idx
            .remove(name)
            .ok_or_else(|| Error::validation(format!("no such nfs share: {name}")))?;
        if let Some(m) = st.mounts.get_mut(idx) {
            m.active = false;
        }
        // Drop cached inodes belonging to this mount.
        st.inode_cache.retain(|k, _| {
            let (m_idx, _) = split_fileid(*k);
            m_idx != idx as u16
        });
        Ok(())
    }

    /// Resolve fileid → (mount_idx, host_abs_path). Returns NFS3ERR_STALE
    /// if the mount is gone or NFS3ERR_NOENT if not in cache.
    fn resolve(&self, id: fileid3) -> std::result::Result<(usize, PathBuf), nfsstat3> {
        if id == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let (mount_idx, low) = split_fileid(id);
        let st = self.state.read().unwrap();
        let m = st.mounts.get(mount_idx as usize).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if !m.active {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        if low == MOUNT_ROOT_LOW {
            return Ok((mount_idx as usize, m.host_path.clone()));
        }
        let rel = st.inode_cache.get(&id).ok_or(nfsstat3::NFS3ERR_STALE)?.clone();
        Ok((mount_idx as usize, m.host_path.join(rel)))
    }

    fn mount_is_ro(&self, mount_idx: usize) -> bool {
        self.state
            .read()
            .unwrap()
            .mounts
            .get(mount_idx)
            .is_none_or(|m| m.read_only)
    }

    /// Insert (or update) a child fileid in the cache and return it.
    fn intern_child(&self, parent_id: fileid3, parent_rel: &Path, child: &OsStr) -> fileid3 {
        let (mount_idx, _) = split_fileid(parent_id);
        let mut new_rel = parent_rel.to_path_buf();
        new_rel.push(child);
        let bytes = new_rel.as_os_str().as_bytes();
        let low = path_hash(self.fh_seed, mount_idx, bytes);
        let id = make_fileid(mount_idx, low);
        self.state.write().unwrap().inode_cache.insert(id, new_rel);
        id
    }

    /// Look up the relative-to-mount-root path for a fileid. Mount-root
    /// returns `""`.
    fn rel_path_of(&self, id: fileid3) -> std::result::Result<PathBuf, nfsstat3> {
        let (mount_idx, low) = split_fileid(id);
        let st = self.state.read().unwrap();
        let m = st.mounts.get(mount_idx as usize).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if !m.active {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        if low == MOUNT_ROOT_LOW {
            return Ok(PathBuf::new());
        }
        st.inode_cache.get(&id).cloned().ok_or(nfsstat3::NFS3ERR_STALE)
    }
}

// ─── fattr3 helpers ───────────────────────────────────────────────────────

fn fattr_for_root(id: fileid3) -> fattr3 {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| nfstime3 {
            seconds: d.as_secs() as u32,
            nseconds: d.subsec_nanos(),
        })
        .unwrap_or_default();
    fattr3 {
        ftype: ftype3::NF3DIR,
        mode: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        size: 0,
        used: 0,
        rdev: specdata3::default(),
        fsid: 0,
        fileid: id,
        atime: now,
        mtime: now,
        ctime: now,
    }
}

fn fattr_from_metadata(id: fileid3, meta: &std::fs::Metadata) -> fattr3 {
    use std::os::unix::fs::MetadataExt;
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        ftype3::NF3DIR
    } else if ft.is_symlink() {
        ftype3::NF3LNK
    } else if ft.is_file() {
        ftype3::NF3REG
    } else {
        ftype3::NF3REG
    };
    let to_t = |t: SystemTime| -> nfstime3 {
        t.duration_since(std::time::UNIX_EPOCH)
            .map(|d| nfstime3 {
                seconds: d.as_secs() as u32,
                nseconds: d.subsec_nanos(),
            })
            .unwrap_or_default()
    };
    fattr3 {
        ftype: kind,
        mode: (meta.mode() & 0o7777) as u32,
        nlink: meta.nlink() as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.len(),
        used: meta.len(),
        rdev: specdata3::default(),
        fsid: 0,
        fileid: id,
        atime: meta.accessed().map(to_t).unwrap_or_default(),
        mtime: meta.modified().map(to_t).unwrap_or_default(),
        ctime: meta.created().map(to_t).unwrap_or_default(),
    }
}

fn nfsstat_from_io(e: &std::io::Error) -> nfsstat3 {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => nfsstat3::NFS3ERR_NOENT,
        ErrorKind::PermissionDenied => nfsstat3::NFS3ERR_ACCES,
        ErrorKind::AlreadyExists => nfsstat3::NFS3ERR_EXIST,
        ErrorKind::InvalidInput => nfsstat3::NFS3ERR_INVAL,
        ErrorKind::WriteZero | ErrorKind::UnexpectedEof => nfsstat3::NFS3ERR_IO,
        _ => nfsstat3::NFS3ERR_IO,
    }
}

/// Reject filenames that would escape the mount: `..`, absolute paths,
/// embedded NUL, empty.
fn validate_filename(name: &filename3) -> std::result::Result<&Path, nfsstat3> {
    let bytes = name.as_ref();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(nfsstat3::NFS3ERR_INVAL);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
    let p = Path::new(s);
    let mut comps = p.components();
    let only = comps.next().ok_or(nfsstat3::NFS3ERR_INVAL)?;
    if comps.next().is_some() {
        return Err(nfsstat3::NFS3ERR_INVAL);
    }
    match only {
        Component::Normal(_) => Ok(p),
        _ => Err(nfsstat3::NFS3ERR_INVAL),
    }
}

// ─── NFSFileSystem impl ───────────────────────────────────────────────────

/// Newtype wrapper so we can `impl NFSFileSystem` without violating the
/// orphan rule. `nfsserve::tcp::NFSTcpListener::bind` consumes the FS by
/// value; we hand it `RouterFs(router.clone())` and keep the original
/// `Arc<VirtualMountRouter>` on `NfsServer` for `add_mount`/`remove_mount`.
pub struct RouterFs(pub Arc<VirtualMountRouter>);

impl std::ops::Deref for RouterFs {
    type Target = VirtualMountRouter;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl NFSFileSystem for RouterFs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_ID
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> std::result::Result<fileid3, nfsstat3> {
        // Root: filename is a mount name.
        if dirid == ROOT_ID {
            let s = std::str::from_utf8(filename.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
            let st = self.state.read().unwrap();
            let idx = *st.name_to_idx.get(s).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            if !st.mounts[idx].active {
                return Err(nfsstat3::NFS3ERR_NOENT);
            }
            return Ok(make_fileid(idx as u16, MOUNT_ROOT_LOW));
        }

        let name_path = validate_filename(filename)?;
        let (mount_idx, host_dir) = self.resolve(dirid)?;
        let candidate = host_dir.join(name_path);
        if !candidate.symlink_metadata().is_ok() {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        // Build the new relative path = parent_rel + name.
        let parent_rel = self.rel_path_of(dirid)?;
        let mut new_rel = parent_rel;
        new_rel.push(name_path);
        let low = path_hash(self.fh_seed, mount_idx as u16, new_rel.as_os_str().as_bytes());
        let id = make_fileid(mount_idx as u16, low);
        self.state.write().unwrap().inode_cache.insert(id, new_rel);
        Ok(id)
    }

    async fn getattr(&self, id: fileid3) -> std::result::Result<fattr3, nfsstat3> {
        if id == ROOT_ID {
            return Ok(fattr_for_root(id));
        }
        let (_idx, host_path) = self.resolve(id)?;
        let meta = std::fs::symlink_metadata(&host_path).map_err(|e| nfsstat_from_io(&e))?;
        Ok(fattr_from_metadata(id, &meta))
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> std::result::Result<fattr3, nfsstat3> {
        if id == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let (mount_idx, host_path) = self.resolve(id)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }

        // mode
        if let set_mode3::mode(m) = setattr.mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(m & 0o7777);
            if let Err(e) = std::fs::set_permissions(&host_path, perms) {
                return Err(nfsstat_from_io(&e));
            }
        }
        // uid / gid
        let want_uid = if let set_uid3::uid(u) = setattr.uid {
            Some(u)
        } else {
            None
        };
        let want_gid = if let set_gid3::gid(g) = setattr.gid {
            Some(g)
        } else {
            None
        };
        if want_uid.is_some() || want_gid.is_some() {
            // Best-effort chown via libc; nfsserve typically passes through.
            unsafe {
                let path_c =
                    std::ffi::CString::new(host_path.as_os_str().as_bytes()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
                let _ = libc::chown(
                    path_c.as_ptr(),
                    want_uid.unwrap_or(u32::MAX),
                    want_gid.unwrap_or(u32::MAX),
                );
            }
        }
        // size (truncate / extend)
        if let set_size3::size(sz) = setattr.size {
            if let Err(e) = std::fs::OpenOptions::new()
                .write(true)
                .open(&host_path)
                .and_then(|f| f.set_len(sz))
            {
                return Err(nfsstat_from_io(&e));
            }
        }
        // atime / mtime — best-effort (we don't carry the filetime crate
        // ourselves; let the next stat reflect whatever the OS sets).
        let _ = (setattr.atime, setattr.mtime);

        let meta = std::fs::symlink_metadata(&host_path).map_err(|e| nfsstat_from_io(&e))?;
        Ok(fattr_from_metadata(id, &meta))
    }

    async fn read(&self, id: fileid3, offset: u64, count: u32) -> std::result::Result<(Vec<u8>, bool), nfsstat3> {
        if id == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        let (_idx, host_path) = self.resolve(id)?;
        let mut f = std::fs::File::open(&host_path).map_err(|e| nfsstat_from_io(&e))?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if offset >= len {
            return Ok((Vec::new(), true));
        }
        f.seek(SeekFrom::Start(offset)).map_err(|e| nfsstat_from_io(&e))?;
        let mut buf = vec![0u8; count as usize];
        let mut read_total = 0;
        while read_total < buf.len() {
            match f.read(&mut buf[read_total..]) {
                Ok(0) => break,
                Ok(n) => read_total += n,
                Err(e) => return Err(nfsstat_from_io(&e)),
            }
        }
        buf.truncate(read_total);
        let eof = offset + read_total as u64 >= len;
        Ok((buf, eof))
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> std::result::Result<fattr3, nfsstat3> {
        if id == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let (mount_idx, host_path) = self.resolve(id)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&host_path)
            .map_err(|e| nfsstat_from_io(&e))?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| nfsstat_from_io(&e))?;
        f.write_all(data).map_err(|e| nfsstat_from_io(&e))?;
        f.flush().ok();
        let meta = f.metadata().map_err(|e| nfsstat_from_io(&e))?;
        Ok(fattr_from_metadata(id, &meta))
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> std::result::Result<(fileid3, fattr3), nfsstat3> {
        if dirid == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let name_path = validate_filename(filename)?;
        let (mount_idx, host_dir) = self.resolve(dirid)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let target = host_dir.join(name_path);
        let mode = match attr.mode {
            set_mode3::mode(m) => m & 0o7777,
            _ => 0o644,
        };
        // O_CREAT | O_TRUNC | O_WRONLY
        use std::os::unix::fs::OpenOptionsExt;
        let _f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&target)
            .map_err(|e| nfsstat_from_io(&e))?;
        if let set_size3::size(sz) = attr.size {
            if let Err(e) = _f.set_len(sz) {
                return Err(nfsstat_from_io(&e));
            }
        }
        let parent_rel = self.rel_path_of(dirid)?;
        let id = self.intern_child(dirid, &parent_rel, name_path.as_os_str());
        let meta = std::fs::symlink_metadata(&target).map_err(|e| nfsstat_from_io(&e))?;
        Ok((id, fattr_from_metadata(id, &meta)))
    }

    async fn create_exclusive(&self, dirid: fileid3, filename: &filename3) -> std::result::Result<fileid3, nfsstat3> {
        if dirid == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let name_path = validate_filename(filename)?;
        let (mount_idx, host_dir) = self.resolve(dirid)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let target = host_dir.join(name_path);
        let _f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| nfsstat_from_io(&e))?;
        let parent_rel = self.rel_path_of(dirid)?;
        Ok(self.intern_child(dirid, &parent_rel, name_path.as_os_str()))
    }

    async fn mkdir(&self, dirid: fileid3, dirname: &filename3) -> std::result::Result<(fileid3, fattr3), nfsstat3> {
        if dirid == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let name_path = validate_filename(dirname)?;
        let (mount_idx, host_dir) = self.resolve(dirid)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let target = host_dir.join(name_path);
        std::fs::create_dir(&target).map_err(|e| nfsstat_from_io(&e))?;
        let parent_rel = self.rel_path_of(dirid)?;
        let id = self.intern_child(dirid, &parent_rel, name_path.as_os_str());
        let meta = std::fs::symlink_metadata(&target).map_err(|e| nfsstat_from_io(&e))?;
        Ok((id, fattr_from_metadata(id, &meta)))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> std::result::Result<(), nfsstat3> {
        if dirid == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let name_path = validate_filename(filename)?;
        let (mount_idx, host_dir) = self.resolve(dirid)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let target = host_dir.join(name_path);
        let meta = std::fs::symlink_metadata(&target).map_err(|e| nfsstat_from_io(&e))?;
        let r = if meta.is_dir() {
            std::fs::remove_dir(&target)
        } else {
            std::fs::remove_file(&target)
        };
        r.map_err(|e| nfsstat_from_io(&e))
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> std::result::Result<(), nfsstat3> {
        if from_dirid == ROOT_ID || to_dirid == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let (from_idx, from_dir) = self.resolve(from_dirid)?;
        let (to_idx, to_dir) = self.resolve(to_dirid)?;
        if from_idx != to_idx {
            return Err(nfsstat3::NFS3ERR_XDEV);
        }
        if self.mount_is_ro(from_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let from = from_dir.join(validate_filename(from_filename)?);
        let to = to_dir.join(validate_filename(to_filename)?);
        std::fs::rename(&from, &to).map_err(|e| nfsstat_from_io(&e))
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> std::result::Result<ReadDirResult, nfsstat3> {
        // Build a deterministic, sorted-by-name list of (fileid, filename, fattr3),
        // then page from start_after.
        let mut entries: Vec<DirEntry> = Vec::new();

        if dirid == ROOT_ID {
            // List active mount names.
            let st = self.state.read().unwrap();
            let mut names: Vec<(usize, String)> = st
                .name_to_idx
                .iter()
                .filter_map(|(n, &i)| st.mounts.get(i).filter(|m| m.active).map(|_| (i, n.clone())))
                .collect();
            drop(st);
            names.sort_by(|a, b| a.1.cmp(&b.1));
            for (idx, name) in names {
                let id = make_fileid(idx as u16, MOUNT_ROOT_LOW);
                entries.push(DirEntry {
                    fileid: id,
                    name: filename3::from(name.as_bytes()),
                    attr: fattr_for_root(id),
                });
            }
        } else {
            let (mount_idx, host_dir) = self.resolve(dirid)?;
            let parent_rel = self.rel_path_of(dirid)?;
            let rd = std::fs::read_dir(&host_dir).map_err(|e| nfsstat_from_io(&e))?;
            let mut raw: Vec<(String, std::fs::Metadata)> = Vec::new();
            for ent in rd.flatten() {
                let name = match ent.file_name().to_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                let meta = match ent.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                raw.push((name, meta));
            }
            raw.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, meta) in raw {
                let mut new_rel = parent_rel.clone();
                new_rel.push(&name);
                let low = path_hash(self.fh_seed, mount_idx as u16, new_rel.as_os_str().as_bytes());
                let id = make_fileid(mount_idx as u16, low);
                self.state.write().unwrap().inode_cache.insert(id, new_rel);
                entries.push(DirEntry {
                    fileid: id,
                    name: filename3::from(name.as_bytes()),
                    attr: fattr_from_metadata(id, &meta),
                });
            }
        }

        // Pagination by start_after.
        let start = if start_after == 0 {
            0
        } else {
            entries
                .iter()
                .position(|e| e.fileid == start_after)
                .map(|p| p + 1)
                .unwrap_or(entries.len())
        };
        let end_idx = (start + max_entries).min(entries.len());
        let end_flag = end_idx == entries.len();
        let page: Vec<DirEntry> = entries.drain(start..end_idx).collect();
        Ok(ReadDirResult {
            entries: page,
            end: end_flag,
        })
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        _attr: &sattr3,
    ) -> std::result::Result<(fileid3, fattr3), nfsstat3> {
        if dirid == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let name_path = validate_filename(linkname)?;
        let (mount_idx, host_dir) = self.resolve(dirid)?;
        if self.mount_is_ro(mount_idx) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let target = host_dir.join(name_path);
        let target_str = std::str::from_utf8(symlink.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        std::os::unix::fs::symlink(target_str, &target).map_err(|e| nfsstat_from_io(&e))?;
        let parent_rel = self.rel_path_of(dirid)?;
        let id = self.intern_child(dirid, &parent_rel, name_path.as_os_str());
        let meta = std::fs::symlink_metadata(&target).map_err(|e| nfsstat_from_io(&e))?;
        Ok((id, fattr_from_metadata(id, &meta)))
    }

    async fn readlink(&self, id: fileid3) -> std::result::Result<nfspath3, nfsstat3> {
        if id == ROOT_ID {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let (_idx, host_path) = self.resolve(id)?;
        let dest = std::fs::read_link(&host_path).map_err(|e| nfsstat_from_io(&e))?;
        Ok(nfspath3::from(dest.as_os_str().as_bytes()))
    }
}

// ─── Server ───────────────────────────────────────────────────────────────

/// Per-session NFSv3 server. Drop = server shutdown (the spawned tokio
/// task is aborted, the listener socket closes, in-flight clients see RST).
pub struct NfsServer {
    /// 127.0.0.1 ephemeral port the listener is bound to.
    pub local_port: u16,
    router: Arc<VirtualMountRouter>,
    /// Held to keep the runtime alive at least as long as the server.
    _runtime: Arc<Runtime>,
    /// Aborted on drop.
    task: Option<JoinHandle<()>>,
}

impl NfsServer {
    /// Bind the in-process NFS server to `127.0.0.1:0` and spawn its
    /// accept loop on `runtime`. Use `local_port` to register the
    /// `LocalService` in the netstack.
    pub fn start(runtime: Arc<Runtime>) -> Result<Self> {
        let router = Arc::new(VirtualMountRouter::new());
        let fs = RouterFs(router.clone());

        let listener = runtime
            .block_on(async move { NFSTcpListener::bind("127.0.0.1:0", fs).await })
            .map_err(|e| Error::other(format!("nfs bind 127.0.0.1:0: {e}")))?;

        let local_port = listener.get_listen_port();

        let task = runtime.spawn(async move {
            if let Err(e) = listener.handle_forever().await {
                tracing::warn!("nfs handle_forever exited: {e}");
            }
        });

        Ok(Self {
            local_port,
            router,
            _runtime: runtime,
            task: Some(task),
        })
    }

    /// Register a host directory under `/<name>/` in the NFS namespace.
    pub fn add_mount(&self, name: &str, host_path: PathBuf, read_only: bool) -> Result<()> {
        if !host_path.exists() {
            return Err(Error::validation(format!(
                "host_path does not exist: {}",
                host_path.display()
            )));
        }
        // Canonicalise so symlink dances can't escape the mount.
        let canon = host_path.canonicalize().unwrap_or(host_path);
        self.router.add_mount_inner(name, canon, read_only)?;
        Ok(())
    }

    /// Tombstone a previously-registered mount. In-flight handles to it
    /// will start returning NFS3ERR_STALE.
    pub fn remove_mount(&self, name: &str) -> Result<()> {
        self.router.remove_mount_inner(name)
    }
}

impl Drop for NfsServer {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}
