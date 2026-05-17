//! Host-side filesystem watcher → FUSE_NOTIFY_INVAL_ENTRY / INVAL_INODE.
//!
//! Translates external (host-side, outside-the-FUSE-session) mutations of
//! a [`LocalDirVfs`](crate::vfs_impls::LocalDirVfs)-style mount root into
//! kernel cache invalidation frames so the guest never sees stale data
//! during our 60 s entry/attr TTL window.
//!
//! Spawned at [`FuseHost::register_mount`](super::FuseHost::register_mount)
//! time when [`VfsBackend::watch_root`](crate::vfs_backend::VfsBackend::watch_root)
//! returns `Some`. Lives on the underlying [`notify::RecommendedWatcher`]
//! thread, which terminates when the [`WatcherHandle`] returned here is
//! dropped (in [`FuseHost::remove_mount`](super::FuseHost::remove_mount)).
//!
//! # Why this exists
//!
//! Without it, the sequence
//!
//! ```text
//! guest: cat /mnt/file        # populates dentry + page cache, TTL=60s
//! host : echo NEW > /backing/file
//! guest: cat /mnt/file        # within 60s -> still sees old bytes
//! ```
//!
//! produces stale reads. The full notify protocol (`Inval::Entry`,
//! `Inval::Inode`) was already wired end-to-end — only the *source* was
//! missing. This module fills that gap on all three host OSes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use notify::event::{EventKind, ModifyKind};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use super::FuseHost;

/// RAII handle that stops the watcher thread when dropped.
///
/// `Drop` runs synchronously; the underlying `notify` watcher's
/// destructor unhooks the OS-level subscription (inotify_rm_watch on
/// Linux, FSEventStreamStop+Release on macOS, CloseHandle on Windows).
pub(super) struct WatcherHandle {
    _watcher: RecommendedWatcher,
}

/// Start watching `root` for external mutations. The watcher will keep
/// running until the returned handle is dropped.
///
/// `host` is held as a `Weak` so the watcher does not extend the
/// FuseHost's lifetime; if the host has been dropped by the time an
/// event arrives, the event is silently ignored.
pub(super) fn spawn_watcher(host: Arc<FuseHost>, mount_id: u32, root: PathBuf) -> Option<WatcherHandle> {
    // Canonicalise so the absolute paths reported in events line up
    // with the root prefix we will strip. `notify` itself does this
    // internally for some backends, but not all of them.
    let root = root.canonicalize().unwrap_or(root);
    let weak: Weak<FuseHost> = Arc::downgrade(&host);

    let handler_root = root.clone();
    let event_handler = move |res: notify::Result<notify::Event>| {
        let event = match res {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!("vfs watcher: event error: {err}");
                return;
            }
        };
        let Some(host) = weak.upgrade() else { return };
        handle_event(&host, mount_id, &handler_root, &event);
    };

    let mut watcher = match RecommendedWatcher::new(event_handler, notify::Config::default()) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                "vfs watcher: cannot construct RecommendedWatcher for {}: {e}",
                root.display()
            );
            return None;
        }
    };
    if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
        tracing::warn!("vfs watcher: cannot watch {}: {e}", root.display());
        return None;
    }
    tracing::debug!("vfs watcher: armed for mount {} at {}", mount_id, root.display());
    Some(WatcherHandle { _watcher: watcher })
}

fn handle_event(host: &FuseHost, mount_id: u32, root: &Path, event: &notify::Event) {
    use EventKind::*;
    // Translate each affected host path → vfs-relative path, then fire
    // INVAL_ENTRY on its parent and (for content changes) INVAL_INODE
    // on the file's own nodeid.
    let want_inode = matches!(
        event.kind,
        Modify(ModifyKind::Data(_)) | Modify(ModifyKind::Any) | Modify(ModifyKind::Metadata(_)),
    );
    // INVAL_ENTRY drops the kernel's cached dentry, forcing the next
    // access to re-LOOKUP and pick up fresh attrs (including size).
    // We trigger it on *any* mutation, not just create/remove/rename,
    // because the kernel may serve stale i_size on a content overwrite
    // even after INVAL_INODE drops the pages.
    let want_entry = matches!(
        event.kind,
        Create(_)
            | Remove(_)
            | Modify(ModifyKind::Name(_))
            | Modify(ModifyKind::Any)
            | Modify(ModifyKind::Data(_))
            | Modify(ModifyKind::Metadata(_)),
    );

    for host_path in &event.paths {
        let Some(vfs_path) = host_to_vfs(root, host_path) else {
            continue;
        };

        if want_entry
            && let Some((parent, name)) = split_parent_name(&vfs_path)
            && let Some(pn) = nodeid_of_dir(host, mount_id, &parent)
        {
            host.notify_entry_external(mount_id, pn, &name);
        }

        if want_inode && let Some(nodeid) = host.id_table_find_path(mount_id, &vfs_path) {
            host.notify_inode_external(mount_id, nodeid);
        }

        // Rename events may report both endpoints in the same event
        // (RenameMode::Both → two paths). The loop above already emits
        // INVAL_ENTRY for each path; nothing extra needed.
    }
}

/// Translate a host-side absolute path to the vfs-relative path the
/// guest knows it as. Returns `None` if `path` is not under `root` or
/// if it *is* `root` itself (the mount root is always nodeid 1; we
/// don't invalidate it).
fn host_to_vfs(root: &Path, path: &Path) -> Option<PathBuf> {
    let rel = path.strip_prefix(root).ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    let mut out = PathBuf::from("/");
    out.push(rel);
    Some(out)
}

/// Split a vfs path `"/a/b/c"` into `(parent_path = "/a/b", name = "c")`.
/// Returns `None` if the path has no parent (i.e. it *is* `/`).
fn split_parent_name(vfs: &Path) -> Option<(PathBuf, String)> {
    let name = vfs.file_name()?.to_str()?.to_string();
    let parent = vfs.parent().unwrap_or_else(|| Path::new("/"));
    let parent = if parent.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        parent.to_path_buf()
    };
    Some((parent, name))
}

/// Resolve a vfs directory path to its nodeid. `/` is always 1; other
/// paths are looked up in the IdTable (which means we only invalidate
/// directories the guest has previously `LOOKUP`'d — exactly the
/// directories whose dentry cache could have a stale entry).
fn nodeid_of_dir(host: &FuseHost, mount_id: u32, vfs_dir: &Path) -> Option<u64> {
    if vfs_dir == Path::new("/") {
        return Some(1);
    }
    host.id_table_find_path(mount_id, vfs_dir)
}
