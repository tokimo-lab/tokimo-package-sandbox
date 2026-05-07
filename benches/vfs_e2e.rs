//! End-to-end VFS bench: real `FuseHost` over a unix `socketpair`,
//! exercising the full wire + dispatch path against a `LocalDirVfs`
//! backed by tmpfs.
//!
//! Bypasses the FUSE kernel layer (which would need root) but captures
//! everything `tokimo-sandbox-fuse` does on the wire: postcard
//! encode/decode, length-prefix framing, real socket I/O, tokio dispatch,
//! `LocalDirVfs` reading/writing real files.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokimo_package_sandbox::vfs_host::FuseHost;
use tokimo_package_sandbox::vfs_impls::LocalDirVfs;
use tokimo_package_sandbox::vfs_protocol::handshake;
use tokimo_package_sandbox::vfs_protocol::wire::blocking as wire;
use tokimo_package_sandbox::vfs_protocol::{Frame, Req, Res};

type PendingMap = Arc<std::sync::Mutex<HashMap<u64, mpsc::Sender<Res>>>>;

struct Client {
    write_file: std::sync::Mutex<std::fs::File>,
    next_req_id: AtomicU64,
    pending: PendingMap,
    bound_mount_id: u32,
}

impl Client {
    fn call(&self, op: Req) -> Res {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(req_id, tx);
        let frame = Frame::Request {
            req_id,
            mount_id: self.bound_mount_id,
            op,
        };
        {
            let mut g = self.write_file.lock().unwrap();
            wire::write_frame(&mut *g, &frame).expect("write_frame");
        }
        rx.recv_timeout(Duration::from_secs(10)).expect("response timeout")
    }
}

struct Harness {
    _rt: tokio::runtime::Runtime,
    client: Arc<Client>,
    tmp: tempfile::TempDir,
    _reader: std::thread::JoinHandle<()>,
}

impl Harness {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        // Seed a few files of varying size used by the benchmarks.
        std::fs::write(tmp.path().join("hello.txt"), b"hello world\n").unwrap();
        let mut big = vec![0xABu8; 1024 * 1024];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        std::fs::write(tmp.path().join("big.bin"), &big).unwrap();
        std::fs::write(tmp.path().join("med.bin"), &big[..65536]).unwrap();
        std::fs::write(tmp.path().join("small.bin"), &big[..4096]).unwrap();

        let host = Arc::new(FuseHost::new());
        host.register_mount("work", LocalDirVfs::arc(tmp.path()), false);

        let (host_fd, client_fd) = pair();

        // Server side.
        let host_clone = host.clone();
        rt.spawn(async move {
            let std_stream = unsafe { StdUnixStream::from_raw_fd(host_fd.into_raw_fd()) };
            std_stream.set_nonblocking(true).unwrap();
            let stream = tokio::net::UnixStream::from_std(std_stream).unwrap();
            let _ = host_clone.serve(stream).await;
        });

        // Client side: handshake.
        let client_std: StdUnixStream = unsafe { StdUnixStream::from_raw_fd(client_fd.into_raw_fd()) };
        let owned: OwnedFd = client_std.into();
        let mut hs_file: std::fs::File = owned.into();
        let bound = handshake::client_handshake(&mut hs_file, "work", "bench").expect("handshake");

        // Dup for separate read fd.
        let raw = hs_file.as_raw_fd();
        let read_raw = unsafe { libc::dup(raw) };
        assert!(read_raw >= 0);
        let read_file = unsafe { std::fs::File::from_raw_fd(read_raw) };

        let pending: PendingMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let pending_thread = pending.clone();
        let reader = std::thread::spawn(move || {
            let mut rf = read_file;
            let mut buf = Vec::with_capacity(8192);
            loop {
                match wire::read_frame_into(&mut rf, &mut buf) {
                    Ok(Some(Frame::Response { req_id, result })) => {
                        if let Some(tx) = pending_thread.lock().unwrap().remove(&req_id) {
                            let _ = tx.send(result);
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => return,
                }
            }
        });

        let client = Arc::new(Client {
            write_file: std::sync::Mutex::new(hs_file),
            next_req_id: AtomicU64::new(1),
            pending,
            bound_mount_id: bound,
        });

        Self {
            _rt: rt,
            client,
            tmp,
            _reader: reader,
        }
    }

    /// Lookup `name` under root and return the nodeid.
    fn lookup(&self, name: &str) -> u64 {
        match self.client.call(Req::Lookup {
            parent_nodeid: 1,
            name: name.into(),
        }) {
            Res::Entry(e) => e.nodeid,
            other => panic!("lookup: {other:?}"),
        }
    }

    fn open(&self, nodeid: u64, flags: u32) -> u64 {
        match self.client.call(Req::Open { nodeid, flags }) {
            Res::OpenOk { fh } => fh,
            other => panic!("open: {other:?}"),
        }
    }

    fn release(&self, fh: u64) {
        match self.client.call(Req::Release { fh }) {
            Res::Ok => {}
            other => panic!("release: {other:?}"),
        }
    }

    fn flush(&self, fh: u64) {
        match self.client.call(Req::Flush { fh }) {
            Res::Ok => {}
            other => panic!("flush: {other:?}"),
        }
    }
}

fn pair() -> (OwnedFd, OwnedFd) {
    let (a, b) = StdUnixStream::pair().unwrap();
    (a.into(), b.into())
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_small_rpc(c: &mut Criterion) {
    let h = Harness::new();
    let nid = h.lookup("hello.txt");

    let mut g = c.benchmark_group("vfs_e2e::small_rpc");
    g.bench_function("getattr", |b| {
        b.iter(|| {
            let _ = h.client.call(Req::GetAttr { nodeid: nid });
        });
    });
    g.bench_function("lookup", |b| {
        b.iter(|| {
            let _ = h.client.call(Req::Lookup {
                parent_nodeid: 1,
                name: "hello.txt".into(),
            });
        });
    });
    g.finish();
}

fn bench_read(c: &mut Criterion) {
    let h = Harness::new();

    let mut g = c.benchmark_group("vfs_e2e::read");
    for &(name, file_name, size) in &[
        ("4k", "small.bin", 4096usize),
        ("64k", "med.bin", 65536),
        ("1m", "big.bin", 1024 * 1024),
    ] {
        let nid = h.lookup(file_name);
        let fh = h.open(nid, 0);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &(fh, size), |b, &(fh, size)| {
            b.iter(|| {
                let res = h.client.call(Req::Read {
                    fh,
                    offset: 0,
                    size: size as u32,
                });
                match res {
                    Res::Bytes(v) => assert_eq!(v.len(), size),
                    other => panic!("{other:?}"),
                }
            });
        });
        h.release(fh);
    }
    g.finish();
}

fn bench_write(c: &mut Criterion) {
    let h = Harness::new();
    // Pre-create a file we'll repeatedly write into.
    std::fs::write(h.tmp.path().join("wbench.bin"), b"").unwrap();
    let nid = h.lookup("wbench.bin");

    let mut g = c.benchmark_group("vfs_e2e::write");
    for &(name, size) in &[("4k", 4096usize), ("64k", 65536), ("1m", 1024 * 1024)] {
        let buf = vec![0xCDu8; size];
        let fh = h.open(nid, 0o2 /* O_RDWR */);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &buf, |b, buf| {
            b.iter(|| {
                let res = h.client.call(Req::Write {
                    fh,
                    offset: 0,
                    data: buf.clone(),
                });
                assert!(matches!(res, Res::Written { .. }));
            });
        });
        h.flush(fh);
        h.release(fh);
    }
    g.finish();
}

criterion_group!(benches, bench_small_rpc, bench_read, bench_write);
criterion_main!(benches);
