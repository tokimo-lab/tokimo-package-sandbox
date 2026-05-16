use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::io::Cursor;
use tokimo_package_sandbox::vfs_protocol::{
    AttrOut, EntryOut, Frame, NodeKind, Req, Res,
    wire::blocking::{read_frame, read_frame_into, write_frame},
};

fn make_small_frame() -> Frame {
    Frame::Request {
        req_id: 1,
        mount_id: 0,
        op: Req::GetAttr { nodeid: 42 },
    }
}

fn make_lookup_frame() -> Frame {
    Frame::Request {
        req_id: 2,
        mount_id: 0,
        op: Req::Lookup {
            parent_nodeid: 1,
            name: "hello_world.txt".into(),
        },
    }
}

fn make_entry_response() -> Frame {
    Frame::Response {
        req_id: 2,
        result: Res::Entry(EntryOut {
            nodeid: 99,
            generation: 1,
            attr: AttrOut {
                size: 12345,
                blocks: 8,
                mtime: 1700000000,
                mode: 0o644,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                kind: NodeKind::File,
                rdev: 0,
            },
        }),
    }
}

fn make_read_response(size: usize) -> Frame {
    Frame::Response {
        req_id: 3,
        result: Res::Bytes(vec![0xAB; size]),
    }
}

fn make_write_request(size: usize) -> Frame {
    Frame::Request {
        req_id: 4,
        mount_id: 0,
        op: Req::Write {
            fh: 7,
            offset: 0,
            data: vec![0xCD; size],
        },
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_write_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("vfs_wire::write_frame");

    let frames: &[(&str, Frame)] = &[
        ("getattr", make_small_frame()),
        ("lookup", make_lookup_frame()),
        ("entry_resp", make_entry_response()),
    ];

    for (name, frame) in frames {
        group.bench_with_input(BenchmarkId::from_parameter(name), frame, |b, frame| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(256);
                write_frame(&mut buf, frame).unwrap();
                buf
            });
        });
    }

    // Large I/O
    for size in [4096, 65536, 1024 * 1024] {
        let frame = make_read_response(size);
        group.bench_with_input(BenchmarkId::new("read_resp_bytes", size), &frame, |b, frame| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(size + 64);
                write_frame(&mut buf, frame).unwrap();
                buf
            });
        });
    }

    for size in [4096, 65536, 1024 * 1024] {
        let frame = make_write_request(size);
        group.bench_with_input(BenchmarkId::new("write_req_data", size), &frame, |b, frame| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(size + 64);
                write_frame(&mut buf, frame).unwrap();
                buf
            });
        });
    }

    group.finish();
}

fn bench_read_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("vfs_wire::read_frame");

    // Pre-serialize frames into buffers
    let cases: Vec<(&str, Vec<u8>)> = [
        ("getattr", make_small_frame()),
        ("lookup", make_lookup_frame()),
        ("entry_resp", make_entry_response()),
    ]
    .into_iter()
    .map(|(name, frame)| {
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        (name, buf)
    })
    .collect();

    for (name, data) in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| {
                let mut cursor = Cursor::new(data);
                read_frame(&mut cursor).unwrap()
            });
        });
    }

    for size in [4096, 65536, 1024 * 1024] {
        let frame = make_read_response(size);
        let mut data = Vec::with_capacity(size + 64);
        write_frame(&mut data, &frame).unwrap();
        group.bench_with_input(BenchmarkId::new("read_resp_bytes", size), &data, |b, data| {
            b.iter(|| {
                let mut cursor = Cursor::new(data);
                read_frame(&mut cursor).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_read_frame_into(c: &mut Criterion) {
    let mut group = c.benchmark_group("vfs_wire::read_frame_into");

    let cases: Vec<(&str, Vec<u8>)> = [
        ("getattr", make_small_frame()),
        ("lookup", make_lookup_frame()),
        ("entry_resp", make_entry_response()),
    ]
    .into_iter()
    .map(|(name, frame)| {
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        (name, buf)
    })
    .collect();

    for (name, data) in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            let mut reuse_buf = Vec::with_capacity(256);
            b.iter(|| {
                let mut cursor = Cursor::new(data);
                read_frame_into(&mut cursor, &mut reuse_buf).unwrap()
            });
        });
    }

    for size in [4096, 65536, 1024 * 1024] {
        let frame = make_read_response(size);
        let mut data = Vec::with_capacity(size + 64);
        write_frame(&mut data, &frame).unwrap();
        group.bench_with_input(BenchmarkId::new("read_resp_bytes", size), &data, |b, data| {
            let mut reuse_buf = Vec::with_capacity(size + 64);
            b.iter(|| {
                let mut cursor = Cursor::new(data);
                read_frame_into(&mut cursor, &mut reuse_buf).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("vfs_wire::roundtrip");

    for size in [0, 4096, 65536, 1024 * 1024] {
        let frame = if size == 0 {
            make_small_frame()
        } else {
            make_read_response(size)
        };
        group.bench_with_input(BenchmarkId::new("bytes", size), &frame, |b, frame| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(size + 64);
                write_frame(&mut buf, frame).unwrap();
                let mut cursor = Cursor::new(&buf);
                read_frame(&mut cursor).unwrap()
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_write_frame,
    bench_read_frame,
    bench_read_frame_into,
    bench_roundtrip
);
criterion_main!(benches);
