//! Measures throughput & latency of the userspace netstack (smoltcp
//! gateway) versus the guest's own kernel loopback. Same style as
//! fuse_pagecache_perf.rs: prints numbers for human inspection, does
//! not hard-assert on absolute timings.
//!
//! Topology under test (NetworkPolicy::AllowAll, Linux backend):
//!
//!   guest python ──tk0──▶ smoltcp ──host kernel──▶ TcpListener (this test)
//!                          ▲                              │
//!                          └──────────────────────────────┘
//!                              host primary IPv4 : ephemeral port
//!
//! Skipped automatically when the host has no IPv4 default route — the
//! AllowAll path needs the host kernel to be able to dial the test
//! listener via its own primary IP.
//!
//! Run:
//!   PATH="$PWD/target/debug:$PATH" cargo test --test netstack_perf -- \
//!       --nocapture --test-threads=1

mod common;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::{NetworkPolicy, Sandbox};

const MB: usize = 1024 * 1024;
const THROUGHPUT_BYTES: usize = 64 * MB;
const LATENCY_ITERS: usize = 2000;

/// Discover the host's primary IPv4 by asking the kernel which source
/// address it would use for an arbitrary public destination. No packets
/// are sent — UDP `connect()` is just a route-table lookup.
fn host_primary_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v) if !v.is_loopback() => Some(v),
        _ => None,
    }
}

/// Bind a TcpListener on 0.0.0.0:0 and drive it on a worker thread,
/// invoking `handler` once per accepted connection. Returns the assigned
/// port and a shutdown flag (set to stop the accept loop).
fn spawn_listener<F>(handler: F) -> (u16, Arc<AtomicBool>)
where
    F: Fn(TcpStream) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("0.0.0.0:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).ok();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let h = Arc::new(handler);
    thread::spawn(move || {
        while !stop_t.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((sock, _)) => {
                    sock.set_nonblocking(false).ok();
                    let h = h.clone();
                    thread::spawn(move || h(sock));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (port, stop)
}

#[test]
fn netstack_perf_smoltcp_vs_loopback() {
    const LABEL: &str = "netperf";

    let host_ip = match host_primary_ipv4() {
        Some(ip) => ip,
        None => {
            eprintln!("[netperf] no primary IPv4 default route on host — skipping");
            return;
        }
    };
    eprintln!("[netperf] host primary IPv4: {host_ip}");

    // SINK: read until EOF, discard. Guest measures TX throughput.
    let (sink_port, sink_stop) = spawn_listener(|mut s: TcpStream| {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    // SRC: blast THROUGHPUT_BYTES then close. Guest measures RX throughput.
    let (src_port, src_stop) = spawn_listener(|mut s: TcpStream| {
        let payload = vec![0xABu8; 256 * 1024];
        let mut sent = 0usize;
        while sent < THROUGHPUT_BYTES {
            let want = (THROUGHPUT_BYTES - sent).min(payload.len());
            if s.write_all(&payload[..want]).is_err() {
                break;
            }
            sent += want;
        }
    });

    // ECHO: 4-byte ping/pong loop. Guest measures RTT.
    let (echo_port, echo_stop) = spawn_listener(|mut s: TcpStream| {
        s.set_nodelay(true).ok();
        let mut buf = [0u8; 64];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // ---------- Sandbox boot ----------
    let mut cfg = config(LABEL);
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Reachability sanity probe — if the host kernel can't reach itself
    // at $host_ip from the namespace where smoltcp's std::net sockets
    // live, every measurement below would just time out.
    sb.write_stdin(
        &shell,
        format!(
            "timeout 5 bash -c 'exec 3<>/dev/tcp/{host_ip}/{sink_port}' \
             && echo NETPERF_REACH_OK || echo NETPERF_REACH_FAIL\n\
             echo NETPERF_REACH_DONE\n",
        )
        .as_bytes(),
    )
    .unwrap();
    let reach = drain_until(&rx, &shell, "NETPERF_REACH_DONE", Duration::from_secs(15));
    if !reach.contains("NETPERF_REACH_OK") {
        eprintln!("[netperf] guest could not reach host {host_ip}:{sink_port} — skipping (probe={reach:?})");
        sb.stop_vm().ok();
        sink_stop.store(true, Ordering::Relaxed);
        src_stop.store(true, Ordering::Relaxed);
        echo_stop.store(true, Ordering::Relaxed);
        return;
    }

    // ---------- Workload script (runs inside guest) ----------
    let script = format!(
        r#"import socket, time, threading

HOST  = "{host_ip}"
SINK  = {sink_port}
SRC   = {src_port}
ECHO  = {echo_port}
N     = {throughput}
ITERS = {iters}
CHUNK = 256 * 1024

def tx(host, port):
    s = socket.create_connection((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    buf = b"\xab" * CHUNK
    sent = 0
    t0 = time.perf_counter()
    while sent < N:
        n = s.send(buf[: min(len(buf), N - sent)])
        if n == 0:
            break
        sent += n
    s.shutdown(socket.SHUT_WR)
    # Wait for peer FIN so we time real bytes-on-wire, not socket buf.
    while s.recv(4096):
        pass
    dt = time.perf_counter() - t0
    s.close()
    return sent, dt

def rx(host, port):
    s = socket.create_connection((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    got = 0
    t0 = time.perf_counter()
    while True:
        b = s.recv(CHUNK)
        if not b:
            break
        got += len(b)
    dt = time.perf_counter() - t0
    s.close()
    return got, dt

def lat(host, port, iters):
    s = socket.create_connection((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    pkt = b"PING"
    for _ in range(50):  # warm
        s.sendall(pkt)
        s.recv(4)
    t0 = time.perf_counter()
    for _ in range(iters):
        s.sendall(pkt)
        r = b""
        while len(r) < 4:
            r += s.recv(4 - len(r))
    dt = time.perf_counter() - t0
    s.close()
    return iters, dt

# Pure-guest-kernel TX baseline on lo (smoltcp NOT involved).
def loop_sink_port():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    def acc():
        c, _ = srv.accept()
        try:
            while c.recv(CHUNK):
                pass
        finally:
            c.close(); srv.close()
    threading.Thread(target=acc, daemon=True).start()
    return port

lp_port = loop_sink_port()
sb, dl = tx("127.0.0.1", lp_port)
print(f"LOOPBACK_TX  bytes={{sb}} dt={{dl:.4f}}s mibps={{sb/dl/1048576:.1f}}")

sb, dt = tx(HOST, SINK)
print(f"SMOLTCP_TX   bytes={{sb}} dt={{dt:.4f}}s mibps={{sb/dt/1048576:.1f}}")

gb, dr = rx(HOST, SRC)
print(f"SMOLTCP_RX   bytes={{gb}} dt={{dr:.4f}}s mibps={{gb/dr/1048576:.1f}}")

it, dl2 = lat(HOST, ECHO, ITERS)
print(f"SMOLTCP_RTT  iters={{it}} dt={{dl2:.4f}}s mean_us={{dl2*1e6/it:.1f}}")

print("NETPERF_DONE")
"#,
        host_ip = host_ip,
        sink_port = sink_port,
        src_port = src_port,
        echo_port = echo_port,
        throughput = THROUGHPUT_BYTES,
        iters = LATENCY_ITERS,
    );

    let ws = workspace_dir(LABEL);
    std::fs::write(ws.join("netperf.py"), &script).expect("write netperf.py");

    sb.write_stdin(&shell, b"python3 /work/netperf.py\n").unwrap();
    let out = drain_until(&rx, &shell, "NETPERF_DONE", Duration::from_secs(240));

    sb.stop_vm().ok();
    sink_stop.store(true, Ordering::Relaxed);
    src_stop.store(true, Ordering::Relaxed);
    echo_stop.store(true, Ordering::Relaxed);

    eprintln!(
        "=== Sandbox netstack perf ({} MiB / {} RTTs) ===\n{}\n=== END ===",
        THROUGHPUT_BYTES / MB,
        LATENCY_ITERS,
        out
    );
    assert!(
        out.contains("NETPERF_DONE"),
        "perf workload did not finish in time: {out:?}"
    );
}
