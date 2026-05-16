//! Built-in [`VfsBackend`] implementations.
//!
//! - [`LocalDirVfs`] — host directory passthrough, equivalent to the old
//!   `Mount.host_path` semantics. Used by `Mount::local_dir(...)`.
//! - [`MemFsVfs`] — in-memory filesystem, tests / fixtures.
//!
//! Both are deliberately straightforward: the FUSE bridge handles caching,
//! handle bookkeeping, and write staging — backends only have to translate
//! one logical operation per trait method.

mod local;
mod mem;
mod meta;
mod sanitize;

#[cfg(target_os = "macos")]
mod macos_xattr;

pub use local::LocalDirVfs;
pub use mem::MemFsVfs;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs_backend::{VfsBackend, VfsError, VfsReader};
    use std::path::Path;
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

    #[cfg(windows)]
    #[tokio::test]
    async fn local_invalid_windows_lookup_name_is_not_found() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        let err = vfs.stat(Path::new("/slide-*.jpg")).await.unwrap_err();
        assert!(matches!(err, VfsError::NotFound));
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

    /// Verify that LocalDirVfs::mknod creates a real AF_UNIX socket
    /// inode and that meta_to_info reports it back as `is_socket=true`.
    /// This is the unit-level analogue of `bind(2)` succeeding inside a
    /// FUSE mount: without `mknod` returning Ok and `stat` round-tripping
    /// the S_IFSOCK bits, AF_UNIX bind/connect on a FUSE-backed path
    /// fails with ENOSYS or ENOTSOCK.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn local_mknod_socket_roundtrip() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        let mk = vfs.as_mknod().expect("LocalDirVfs supports mknod");
        // S_IFSOCK | 0666
        mk.mknod(Path::new("/foo.sock"), 0o140666, 0).await.unwrap();

        let info = vfs.stat(Path::new("/foo.sock")).await.unwrap();
        assert!(info.is_socket, "expected is_socket=true, got {info:?}");
        assert!(!info.is_dir);
        assert!(!info.is_fifo);
    }

    /// Same as above but for FIFOs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn local_mknod_fifo_roundtrip() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        let mk = vfs.as_mknod().unwrap();
        // S_IFIFO | 0644
        mk.mknod(Path::new("/p"), 0o010644, 0).await.unwrap();

        let info = vfs.stat(Path::new("/p")).await.unwrap();
        assert!(info.is_fifo, "expected is_fifo=true, got {info:?}");
        assert!(!info.is_socket);
    }

    /// Unprivileged callers cannot create device nodes; mknod should
    /// surface EPERM (mapped to PermissionDenied) rather than silently
    /// creating a regular file.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_mknod_blockdev_returns_eperm() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());

        let mk = vfs.as_mknod().unwrap();
        // S_IFBLK | 0600
        let err = mk
            .mknod(Path::new("/blk"), 0o060600, 0)
            .await
            .expect_err("block dev mknod must fail unprivileged");
        assert!(
            matches!(err, VfsError::PermissionDenied | VfsError::Io(_)),
            "unexpected err: {err:?}"
        );
    }

    // ---- v3: link / access / xattrs ---------------------------------------

    #[tokio::test]
    async fn local_link_roundtrip() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        vfs.as_put()
            .unwrap()
            .put(Path::new("/src.txt"), b"hi".to_vec())
            .await
            .unwrap();

        let lk = vfs.as_link().expect("link cap");
        lk.hard_link(Path::new("/src.txt"), Path::new("/dst.txt"))
            .await
            .unwrap();

        let stat = vfs.stat(Path::new("/dst.txt")).await.unwrap();
        assert_eq!(stat.size, 2);
    }

    #[tokio::test]
    async fn local_access_grants_existing_file() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        vfs.as_put().unwrap().put(Path::new("/a"), b"x".to_vec()).await.unwrap();

        let ac = vfs.as_access().expect("access cap");
        // F_OK = 0
        ac.access(Path::new("/a"), 0).await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_xattr_roundtrip() {
        let dir = tempdir().unwrap();
        let vfs = LocalDirVfs::new(dir.path());
        vfs.as_put().unwrap().put(Path::new("/x"), b"d".to_vec()).await.unwrap();

        let xa = vfs.as_xattr().expect("xattr cap");
        // tmpfs may reject user.* xattrs depending on mount options; tolerate.
        let set = xa.set_xattr(Path::new("/x"), "user.foo", b"bar", 0).await;
        if set.is_err() {
            return;
        }
        let got = xa.get_xattr(Path::new("/x"), "user.foo").await.unwrap();
        assert_eq!(got, b"bar");

        let names = xa.list_xattr(Path::new("/x")).await.unwrap();
        // NUL-separated names — check presence of "user.foo".
        let contains = names.split(|b| *b == 0).any(|n| n == b"user.foo");
        assert!(contains, "names blob did not contain user.foo: {names:?}");

        xa.remove_xattr(Path::new("/x"), "user.foo").await.unwrap();
        let err = xa.get_xattr(Path::new("/x"), "user.foo").await.unwrap_err();
        assert!(matches!(err, VfsError::NoData(_)), "expected NoData, got {err:?}");
    }
}
