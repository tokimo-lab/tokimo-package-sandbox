//! Built-in [`VfsBackend`] implementations.
//!
//! - [`LocalDirVfs`] — host directory passthrough, equivalent to the old
//!   `Mount.host_path` semantics. Used by `Mount::local_dir(...)`.
//! - [`MemFsVfs`] — in-memory filesystem, tests / fixtures.
//!
//! Both are deliberately straightforward: the FUSE bridge handles caching,
//! handle bookkeeping, and write staging — backends only have to translate
//! one logical operation per trait method.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::vfs_backend::{
    VfsBackend, VfsCopy, VfsDeleteDir, VfsDeleteFile, VfsError, VfsFileInfo, VfsMkdir, VfsMove, VfsPut, VfsReader,
    VfsRename, VfsResolveLocal, VfsResult,
};

// ---------------------------------------------------------------------------
// Path sanitisation
// ---------------------------------------------------------------------------

/// Reject `..`, absolute roots after the leading `/`, and any non-Normal
/// components. The bridge already guarantees this at the protocol layer,
/// but defence-in-depth: backends do their own check.
fn sanitize(path: &Path) -> VfsResult<&Path> {
    for c in path.components() {
        match c {
            Component::RootDir | Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(VfsError::InvalidArgument(format!(
                    "path contains ..: {}",
                    path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(VfsError::InvalidArgument(format!(
                    "path has prefix: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(path)
}

/// Strip a leading `/` so we can join under a host root.
fn relative_under(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

// ===========================================================================
// LocalDirVfs
// ===========================================================================

/// Maps the export root to a real host directory. All ops are forwarded to
/// `tokio::fs` / `std::fs`. Implements every optional capability.
#[derive(Debug)]
pub struct LocalDirVfs {
    root: PathBuf,
}

impl LocalDirVfs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn arc(root: impl Into<PathBuf>) -> Arc<dyn VfsBackend> {
        Arc::new(Self::new(root))
    }

    fn host_join(&self, path: &Path) -> VfsResult<PathBuf> {
        sanitize(path)?;
        Ok(self.root.join(relative_under(path)))
    }
}

#[async_trait]
impl VfsReader for LocalDirVfs {
    async fn list(&self, path: &Path) -> VfsResult<Vec<VfsFileInfo>> {
        let host = self.host_join(path)?;
        let mut rd = tokio::fs::read_dir(&host).await?;
        let mut out = Vec::new();
        while let Some(entry) = rd.next_entry().await? {
            let md = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue, // skip racing-deleted entries
            };
            out.push(meta_to_info(entry.file_name().to_string_lossy().into_owned(), md));
        }
        Ok(out)
    }

    async fn stat(&self, path: &Path) -> VfsResult<VfsFileInfo> {
        let host = self.host_join(path)?;
        let md = tokio::fs::metadata(&host).await?;
        let name = host
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(meta_to_info(name, md))
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> VfsResult<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let host = self.host_join(path)?;
        let mut f = tokio::fs::File::open(&host).await?;
        if offset > 0 {
            f.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        let mut buf = match limit {
            Some(l) => Vec::with_capacity(l.min(1024 * 1024) as usize),
            None => Vec::new(),
        };
        match limit {
            Some(l) => {
                let mut take = f.take(l);
                take.read_to_end(&mut buf).await?;
            }
            None => {
                f.read_to_end(&mut buf).await?;
            }
        }
        Ok(buf)
    }
}

#[async_trait]
impl VfsMkdir for LocalDirVfs {
    async fn mkdir(&self, path: &Path) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::create_dir(&host).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsDeleteFile for LocalDirVfs {
    async fn delete_file(&self, path: &Path) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::remove_file(&host).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsDeleteDir for LocalDirVfs {
    async fn delete_dir(&self, path: &Path) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::remove_dir(&host).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsRename for LocalDirVfs {
    async fn rename(&self, from: &Path, to: &Path) -> VfsResult<()> {
        let f = self.host_join(from)?;
        let t = self.host_join(to)?;
        tokio::fs::rename(&f, &t).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsMove for LocalDirVfs {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> VfsResult<()> {
        let f = self.host_join(from)?;
        let t_dir = self.host_join(to_dir)?;
        let name = f
            .file_name()
            .ok_or_else(|| VfsError::InvalidArgument("from has no file name".into()))?;
        tokio::fs::rename(&f, t_dir.join(name)).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsCopy for LocalDirVfs {
    async fn copy(&self, from: &Path, to: &Path) -> VfsResult<()> {
        let f = self.host_join(from)?;
        let t = self.host_join(to)?;
        tokio::fs::copy(&f, &t).await?;
        Ok(())
    }
}

#[async_trait]
impl VfsPut for LocalDirVfs {
    async fn put(&self, path: &Path, data: Vec<u8>) -> VfsResult<()> {
        let host = self.host_join(path)?;
        tokio::fs::write(&host, data).await?;
        Ok(())
    }
}

impl VfsResolveLocal for LocalDirVfs {
    fn resolve_real_path(&self, path: &Path) -> Option<PathBuf> {
        sanitize(path).ok()?;
        Some(self.root.join(relative_under(path)))
    }
}

impl VfsBackend for LocalDirVfs {
    fn as_mkdir(&self) -> Option<&dyn VfsMkdir> {
        Some(self)
    }
    fn as_delete_file(&self) -> Option<&dyn VfsDeleteFile> {
        Some(self)
    }
    fn as_delete_dir(&self) -> Option<&dyn VfsDeleteDir> {
        Some(self)
    }
    fn as_rename(&self) -> Option<&dyn VfsRename> {
        Some(self)
    }
    fn as_move(&self) -> Option<&dyn VfsMove> {
        Some(self)
    }
    fn as_copy(&self) -> Option<&dyn VfsCopy> {
        Some(self)
    }
    fn as_put(&self) -> Option<&dyn VfsPut> {
        Some(self)
    }
    fn as_resolve_local(&self) -> Option<&dyn VfsResolveLocal> {
        Some(self)
    }
}

fn meta_to_info(name: String, md: std::fs::Metadata) -> VfsFileInfo {
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(md.permissions().mode() & 0o7777)
        }
        #[cfg(not(unix))]
        {
            None
        }
    };
    VfsFileInfo {
        name,
        size: md.len(),
        is_dir: md.is_dir(),
        modified: md.modified().ok(),
        mode,
    }
}

// ===========================================================================
// MemFsVfs (test fixture, also useful for "synthetic mount" use cases)
// ===========================================================================

/// In-memory filesystem keyed by absolute path. Implements the full
/// trait suite. **Not** intended for production data — locking is coarse
/// and there's no eviction.
#[derive(Debug, Default)]
pub struct MemFsVfs {
    inner: Mutex<MemFsInner>,
}

#[derive(Debug)]
struct MemFsInner {
    /// Map of absolute (canonical, leading-slash) path → entry.
    /// `/` is always present and is a directory.
    entries: HashMap<PathBuf, MemEntry>,
}

#[derive(Debug, Clone)]
enum MemEntry {
    Dir { modified: SystemTime },
    File { data: Vec<u8>, modified: SystemTime },
}

impl Default for MemFsInner {
    fn default() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            PathBuf::from("/"),
            MemEntry::Dir {
                modified: SystemTime::now(),
            },
        );
        Self { entries }
    }
}

impl MemFsVfs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arc() -> Arc<dyn VfsBackend> {
        Arc::new(Self::new())
    }

    fn key(path: &Path) -> VfsResult<PathBuf> {
        sanitize(path)?;
        let mut p = PathBuf::from("/");
        for c in path.components() {
            if let Component::Normal(n) = c {
                p.push(n);
            }
        }
        Ok(p)
    }

    fn parent_must_exist(inner: &MemFsInner, key: &Path) -> VfsResult<()> {
        let parent = key
            .parent()
            .ok_or_else(|| VfsError::InvalidArgument("no parent".into()))?;
        match inner.entries.get(parent) {
            Some(MemEntry::Dir { .. }) => Ok(()),
            Some(MemEntry::File { .. }) => Err(VfsError::NotDir),
            None => Err(VfsError::NotFound),
        }
    }
}

#[async_trait]
impl VfsReader for MemFsVfs {
    async fn list(&self, path: &Path) -> VfsResult<Vec<VfsFileInfo>> {
        let k = Self::key(path)?;
        let inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::Dir { .. }) => {}
            Some(MemEntry::File { .. }) => return Err(VfsError::NotDir),
            None => return Err(VfsError::NotFound),
        }
        let mut out = Vec::new();
        for (p, e) in inner.entries.iter() {
            if p.parent() == Some(&k) && p != &k {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push(entry_to_info(name, e));
            }
        }
        Ok(out)
    }

    async fn stat(&self, path: &Path) -> VfsResult<VfsFileInfo> {
        let k = Self::key(path)?;
        let inner = self.inner.lock().await;
        let e = inner.entries.get(&k).ok_or(VfsError::NotFound)?;
        let name = if k == Path::new("/") {
            String::new()
        } else {
            k.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        Ok(entry_to_info(name, e))
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> VfsResult<Vec<u8>> {
        let k = Self::key(path)?;
        let inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::File { data, .. }) => {
                let start = (offset as usize).min(data.len());
                let end = match limit {
                    Some(l) => (start + l as usize).min(data.len()),
                    None => data.len(),
                };
                Ok(data[start..end].to_vec())
            }
            Some(MemEntry::Dir { .. }) => Err(VfsError::IsDir),
            None => Err(VfsError::NotFound),
        }
    }
}

#[async_trait]
impl VfsMkdir for MemFsVfs {
    async fn mkdir(&self, path: &Path) -> VfsResult<()> {
        let k = Self::key(path)?;
        let mut inner = self.inner.lock().await;
        if inner.entries.contains_key(&k) {
            return Err(VfsError::AlreadyExists);
        }
        Self::parent_must_exist(&inner, &k)?;
        inner.entries.insert(
            k,
            MemEntry::Dir {
                modified: SystemTime::now(),
            },
        );
        Ok(())
    }
}

#[async_trait]
impl VfsDeleteFile for MemFsVfs {
    async fn delete_file(&self, path: &Path) -> VfsResult<()> {
        let k = Self::key(path)?;
        let mut inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::File { .. }) => {
                inner.entries.remove(&k);
                Ok(())
            }
            Some(MemEntry::Dir { .. }) => Err(VfsError::IsDir),
            None => Err(VfsError::NotFound),
        }
    }
}

#[async_trait]
impl VfsDeleteDir for MemFsVfs {
    async fn delete_dir(&self, path: &Path) -> VfsResult<()> {
        let k = Self::key(path)?;
        if k == Path::new("/") {
            return Err(VfsError::PermissionDenied);
        }
        let mut inner = self.inner.lock().await;
        match inner.entries.get(&k) {
            Some(MemEntry::Dir { .. }) => {}
            Some(MemEntry::File { .. }) => return Err(VfsError::NotDir),
            None => return Err(VfsError::NotFound),
        }
        // dir must be empty
        let has_child = inner.entries.keys().any(|p| p.parent() == Some(&k) && p != &k);
        if has_child {
            return Err(VfsError::Other("directory not empty".into()));
        }
        inner.entries.remove(&k);
        Ok(())
    }
}

#[async_trait]
impl VfsRename for MemFsVfs {
    async fn rename(&self, from: &Path, to: &Path) -> VfsResult<()> {
        let kf = Self::key(from)?;
        let kt = Self::key(to)?;
        let mut inner = self.inner.lock().await;
        let entry = inner.entries.remove(&kf).ok_or(VfsError::NotFound)?;
        Self::parent_must_exist(&inner, &kt)?;
        inner.entries.insert(kt, entry);
        Ok(())
    }
}

#[async_trait]
impl VfsPut for MemFsVfs {
    async fn put(&self, path: &Path, data: Vec<u8>) -> VfsResult<()> {
        let k = Self::key(path)?;
        let mut inner = self.inner.lock().await;
        Self::parent_must_exist(&inner, &k)?;
        if let Some(MemEntry::Dir { .. }) = inner.entries.get(&k) {
            return Err(VfsError::IsDir);
        }
        inner.entries.insert(
            k,
            MemEntry::File {
                data,
                modified: SystemTime::now(),
            },
        );
        Ok(())
    }
}

impl VfsBackend for MemFsVfs {
    fn as_mkdir(&self) -> Option<&dyn VfsMkdir> {
        Some(self)
    }
    fn as_delete_file(&self) -> Option<&dyn VfsDeleteFile> {
        Some(self)
    }
    fn as_delete_dir(&self) -> Option<&dyn VfsDeleteDir> {
        Some(self)
    }
    fn as_rename(&self) -> Option<&dyn VfsRename> {
        Some(self)
    }
    fn as_put(&self) -> Option<&dyn VfsPut> {
        Some(self)
    }
}

fn entry_to_info(name: String, entry: &MemEntry) -> VfsFileInfo {
    match entry {
        MemEntry::Dir { modified } => VfsFileInfo {
            name,
            size: 0,
            is_dir: true,
            modified: Some(*modified),
            mode: Some(0o755),
        },
        MemEntry::File { data, modified } => VfsFileInfo {
            name,
            size: data.len() as u64,
            is_dir: false,
            modified: Some(*modified),
            mode: Some(0o644),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // -- LocalDirVfs ---------------------------------------------------------

    #[tokio::test]
    async fn local_list_stat_read() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"world").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let vfs = LocalDirVfs::new(dir.path());

        let mut entries = vfs.list(Path::new("/")).await.unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "hello.txt");
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].size, 5);
        assert_eq!(entries[1].name, "sub");
        assert!(entries[1].is_dir);

        let s = vfs.stat(Path::new("/hello.txt")).await.unwrap();
        assert_eq!(s.name, "hello.txt");
        assert_eq!(s.size, 5);

        let bytes = vfs.read_bytes(Path::new("/hello.txt"), 0, None).await.unwrap();
        assert_eq!(bytes, b"world");

        let bytes = vfs.read_bytes(Path::new("/hello.txt"), 1, Some(3)).await.unwrap();
        assert_eq!(bytes, b"orl");
    }

    #[tokio::test]
    async fn local_write_path() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        vfs.as_put()
            .unwrap()
            .put(Path::new("/a.txt"), b"hi".to_vec())
            .await
            .unwrap();
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"hi");

        vfs.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        assert!(dir.path().join("d").is_dir());

        vfs.as_rename()
            .unwrap()
            .rename(Path::new("/a.txt"), Path::new("/b.txt"))
            .await
            .unwrap();
        assert!(dir.path().join("b.txt").exists());

        vfs.as_delete_file()
            .unwrap()
            .delete_file(Path::new("/b.txt"))
            .await
            .unwrap();
        assert!(!dir.path().join("b.txt").exists());

        vfs.as_delete_dir().unwrap().delete_dir(Path::new("/d")).await.unwrap();
    }

    #[tokio::test]
    async fn local_rejects_dotdot() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        let err = vfs.stat(Path::new("/../../etc/passwd")).await.unwrap_err();
        assert!(matches!(err, VfsError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn local_resolve_real() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        let p = vfs.as_resolve_local().unwrap().resolve_real_path(Path::new("/foo/bar"));
        assert_eq!(p, Some(dir.path().join("foo/bar")));
    }

    // -- MemFsVfs ------------------------------------------------------------

    #[tokio::test]
    async fn mem_basic_lifecycle() {
        let vfs = MemFsVfs::new();

        // empty root
        let entries = vfs.list(Path::new("/")).await.unwrap();
        assert!(entries.is_empty());

        // mkdir + put
        vfs.as_mkdir().unwrap().mkdir(Path::new("/sub")).await.unwrap();
        vfs.as_put()
            .unwrap()
            .put(Path::new("/sub/a"), b"hello".to_vec())
            .await
            .unwrap();

        // read back
        let bytes = vfs.read_bytes(Path::new("/sub/a"), 0, None).await.unwrap();
        assert_eq!(bytes, b"hello");

        // partial read
        let bytes = vfs.read_bytes(Path::new("/sub/a"), 1, Some(3)).await.unwrap();
        assert_eq!(bytes, b"ell");

        // list
        let entries = vfs.list(Path::new("/sub")).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[0].size, 5);

        // rename
        vfs.as_rename()
            .unwrap()
            .rename(Path::new("/sub/a"), Path::new("/sub/b"))
            .await
            .unwrap();
        assert!(matches!(vfs.stat(Path::new("/sub/a")).await, Err(VfsError::NotFound)));

        // delete
        vfs.as_delete_file()
            .unwrap()
            .delete_file(Path::new("/sub/b"))
            .await
            .unwrap();
        vfs.as_delete_dir()
            .unwrap()
            .delete_dir(Path::new("/sub"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mem_dir_not_empty() {
        let vfs = MemFsVfs::new();
        vfs.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        vfs.as_put()
            .unwrap()
            .put(Path::new("/d/x"), b"x".to_vec())
            .await
            .unwrap();
        let err = vfs
            .as_delete_dir()
            .unwrap()
            .delete_dir(Path::new("/d"))
            .await
            .unwrap_err();
        assert!(matches!(err, VfsError::Other(_)));
    }

    #[tokio::test]
    async fn mem_isdir_notdir() {
        let vfs = MemFsVfs::new();
        vfs.as_mkdir().unwrap().mkdir(Path::new("/d")).await.unwrap();
        assert!(matches!(
            vfs.read_bytes(Path::new("/d"), 0, None).await,
            Err(VfsError::IsDir)
        ));

        vfs.as_put().unwrap().put(Path::new("/f"), b"x".to_vec()).await.unwrap();
        assert!(matches!(vfs.list(Path::new("/f")).await, Err(VfsError::NotDir)));
    }
}
