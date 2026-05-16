//! [`MemFsVfs`] — in-memory filesystem (tests / fixtures).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::vfs_backend::{
    VfsBackend, VfsDeleteDir, VfsDeleteFile, VfsError, VfsFileInfo, VfsMkdir, VfsPut, VfsReader, VfsRename, VfsResult,
};

use super::sanitize::sanitize;

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
        MemEntry::Dir { modified } => VfsFileInfo::basic(name, 0, true, Some(0o755), Some(*modified)),
        MemEntry::File { data, modified } => {
            VfsFileInfo::basic(name, data.len() as u64, false, Some(0o644), Some(*modified))
        }
    }
}
