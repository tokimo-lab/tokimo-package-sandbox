//! Userspace network stack — replaces HCN NAT for `NetworkPolicy::AllowAll`.
//!
//! Architecture:
//!
//! ```text
//!   Guest tk0 (TUN, 192.168.127.2/24, gw .1)
//!     ↕ length-prefixed Ethernet frames over hvsock
//!   Host gateway smoltcp Interface (192.168.127.1/24, any_ip=true)
//!     - per-flow TCP socket created on demand on first SYN
//!     - upstream connect via std::net::TcpStream
//!     - per-flow UDP socket created on demand on first datagram
//!     - upstream send/recv via std::net::UdpSocket
//! ```
//!
//! Wire framing on the hvsock: `u16-be length || ethernet frame`. Matches the
//! framing the guest-side `tokimo-tun-pump` uses.
//!
//! See `docs/cowork-networking-reverse-engineering.md` for the rationale
//! (cowork's gvisor-tap-vsock + this Rust/smoltcp port both bypass kernel
//! NAT and therefore the Windows host's `Forwarding=Disabled` issue).

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel as chan;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    IpListenEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket,
};

// ─── Topology constants ──────────────────────────────────────────────────────

/// Gateway (host) IP — what the guest sets as default route.
pub const HOST_IP: Ipv4Address = Ipv4Address::new(192, 168, 127, 1);
/// Guest IP — assigned to the guest TUN interface by `init.sh`.
pub const GUEST_IP: Ipv4Address = Ipv4Address::new(192, 168, 127, 2);
/// Subnet prefix length.
pub const SUBNET_PREFIX: u8 = 24;
/// Gateway MAC — synthetic, picked outside the IANA OUI space.
pub const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
/// Guest MAC — must match the MAC `tokimo-tun-pump` programs into tk0.
pub const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
/// MTU advertised on the gateway interface. 1400 leaves headroom for any
/// future encapsulation; matches cowork.
pub const MTU: usize = 1400;

// ─── Hvsock-backed Device ────────────────────────────────────────────────────

/// Smoltcp `Device` implementation backed by two channels owned by the main
/// loop. The reader thread pumps `u16-be`-length-prefixed frames from the
/// hvsock into `rx_in`; the writer thread reads outbound frames from
/// `tx_out` and writes them back. The device itself is purely a passthrough.
struct HvsockDevice {
    rx: chan::Receiver<Vec<u8>>,
    tx: chan::Sender<Vec<u8>>,
}

struct HvsockRxToken(Vec<u8>);
struct HvsockTxToken(chan::Sender<Vec<u8>>);

impl RxToken for HvsockRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for HvsockTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
        r
    }
}

impl Device for HvsockDevice {
    type RxToken<'a> = HvsockRxToken;
    type TxToken<'a> = HvsockTxToken;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx
            .try_recv()
            .ok()
            .map(|frame| (HvsockRxToken(frame), HvsockTxToken(self.tx.clone())))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(HvsockTxToken(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU + 14; // + Ethernet header
        caps
    }
}

// ─── Frame I/O on hvsock ────────────────────────────────────────────────────

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr)?;
    let len = u16::from_be_bytes(hdr) as usize;
    if len == 0 || len > 65535 {
        return Err(std::io::Error::other(format!("netstack: bad frame len {len}")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame<W: Write>(w: &mut W, frame: &[u8]) -> std::io::Result<()> {
    if frame.len() > 65535 {
        return Err(std::io::Error::other("netstack: frame too large"));
    }
    let hdr = (frame.len() as u16).to_be_bytes();
    w.write_all(&hdr)?;
    w.write_all(frame)?;
    Ok(())
}

// ─── Flow tracking ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct TcpKey {
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
}

/// State for one upstream TCP proxy connection.
struct TcpFlow {
    handle: SocketHandle,
    /// Send bytes from upstream → guest (main loop drains and writes to socket).
    upstream_to_guest_rx: chan::Receiver<Vec<u8>>,
    /// Send bytes from guest → upstream (proxy thread reads and writes to TcpStream).
    guest_to_upstream_tx: chan::Sender<Vec<u8>>,
    /// Set true when the proxy thread (or upstream) decided we should close.
    upstream_closed: Arc<AtomicBool>,
    /// Last time we saw activity (for idle GC).
    last_activity: Instant,
    /// Whether we already started shutting down.
    closed: bool,
}

/// State for one upstream UDP "flow" (per src+dst tuple, NAT-style).
struct UdpFlow {
    upstream: Arc<UdpSocket>,
    dst: SocketAddr,
    last_activity: Instant,
    /// Set when the recv thread should stop.
    shutdown: Arc<AtomicBool>,
    _join: thread::JoinHandle<()>,
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Spawn the netstack on a fresh thread bound to the given hvsock connection.
///
/// The connection is two halves of a single duplex socket; we read frames
/// from `read_half` and write outbound frames to `write_half`. Returns a
/// JoinHandle so the caller can wait on shutdown if desired.
///
/// `shutdown` is checked periodically; setting it stops the loop within
/// ~50ms.
pub fn spawn(
    read_half: Box<dyn Read + Send>,
    write_half: Box<dyn Write + Send>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("tokimo-netstack".into())
        .spawn(move || {
            if let Err(e) = run(read_half, write_half, shutdown) {
                eprintln!("[netstack] fatal: {e}");
            }
        })
        .expect("spawn netstack thread")
}

fn run(
    mut read_half: Box<dyn Read + Send>,
    write_half: Box<dyn Write + Send>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    // ── Spawn frame reader/writer threads bridging hvsock ↔ device channels.
    let (rx_in_tx, rx_in_rx) = chan::bounded::<Vec<u8>>(256);
    let (tx_out_tx, tx_out_rx) = chan::bounded::<Vec<u8>>(256);

    let shutdown_r = Arc::clone(&shutdown);
    thread::Builder::new()
        .name("netstack-rx".into())
        .spawn(move || {
            while !shutdown_r.load(Ordering::Relaxed) {
                match read_frame(&mut read_half) {
                    Ok(f) => {
                        if rx_in_tx.send(f).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[netstack-rx] read end: {e}");
                        break;
                    }
                }
            }
        })?;

    let shutdown_w = Arc::clone(&shutdown);
    let writer = Arc::new(Mutex::new(write_half));
    let writer_thread = Arc::clone(&writer);
    thread::Builder::new()
        .name("netstack-tx".into())
        .spawn(move || {
            while !shutdown_w.load(Ordering::Relaxed) {
                match tx_out_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(frame) => {
                        let mut w = writer_thread.lock().unwrap();
                        if let Err(e) = write_frame(&mut *w, &frame) {
                            eprintln!("[netstack-tx] write end: {e}");
                            break;
                        }
                    }
                    Err(chan::RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        })?;

    // ── Build the smoltcp Interface ─────────────────────────────────────
    let mut device = HvsockDevice {
        rx: rx_in_rx.clone(),
        tx: tx_out_tx.clone(),
    };
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(HOST_MAC)));
    config.random_seed = rand_seed();
    let mut iface = Interface::new(config, &mut device, smol_now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(HOST_IP), SUBNET_PREFIX))
            .ok();
    });
    // Accept packets to ANY destination IP (transparent proxy mode).
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_flows: HashMap<TcpKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<UdpKey, UdpFlow> = HashMap::new();

    eprintln!(
        "[netstack] gateway {}/{} ↔ guest {}/{} ready",
        HOST_IP, SUBNET_PREFIX, GUEST_IP, SUBNET_PREFIX
    );

    let idle_timeout = Duration::from_secs(120);

    // ── Main event loop ─────────────────────────────────────────────────
    while !shutdown.load(Ordering::Relaxed) {
        // 1. Pre-parse pending RX frames to register listeners *before*
        //    smoltcp processes them. We only peek (clone) at the front
        //    of the queue; the actual receive is done by smoltcp via the
        //    Device's `receive()` callback.
        //
        //    Strategy: drain the channel into a local buffer, inspect each,
        //    create listeners as needed, then re-feed via a one-shot queue.
        let mut staged: Vec<Vec<u8>> = Vec::new();
        while let Ok(frame) = rx_in_rx.try_recv() {
            inspect_and_register(&frame, &mut sockets, &mut tcp_flows, &mut udp_flows, &tx_out_tx);
            staged.push(frame);
        }
        // Re-inject (preserve order) into a transient channel that the
        // device pulls from.
        if !staged.is_empty() {
            let (re_tx, re_rx) = chan::unbounded::<Vec<u8>>();
            for f in staged.drain(..) {
                let _ = re_tx.send(f);
            }
            // Replace device's rx for this poll burst.
            let mut burst_dev = HvsockDevice {
                rx: re_rx,
                tx: tx_out_tx.clone(),
            };
            // Drain everything in this burst.
            loop {
                use smoltcp::iface::PollResult;
                match iface.poll(smol_now(), &mut burst_dev, &mut sockets) {
                    PollResult::SocketStateChanged => continue,
                    PollResult::None => break,
                }
            }
        } else {
            // No new frames — still poll to drive timers/retransmits.
            iface.poll(smol_now(), &mut device, &mut sockets);
        }

        // 2. Service TCP flows: pump bytes between smoltcp socket and proxy.
        let now = Instant::now();
        let mut tcp_to_remove: Vec<TcpKey> = Vec::new();
        for (key, flow) in tcp_flows.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
            // Established → spawn proxy if not yet (signaled by upstream_closed
            // being attached). Proxy thread is spawned at register time.

            // Pump guest → upstream: drain socket recv buffer, push to channel.
            if socket.can_recv() {
                let _ = socket.recv(|buf| {
                    if !buf.is_empty() {
                        let _ = flow.guest_to_upstream_tx.send(buf.to_vec());
                        flow.last_activity = now;
                    }
                    (buf.len(), ())
                });
            }
            // Pump upstream → guest: drain channel, send into socket.
            while let Ok(buf) = flow.upstream_to_guest_rx.try_recv() {
                let mut off = 0;
                while off < buf.len() {
                    match socket.send_slice(&buf[off..]) {
                        Ok(0) => break, // buffer full
                        Ok(n) => off += n,
                        Err(_) => break,
                    }
                }
                flow.last_activity = now;
            }

            // Upstream signalled close: half-close.
            if flow.upstream_closed.load(Ordering::Relaxed) && !flow.closed {
                socket.close();
                flow.closed = true;
            }

            // Reap fully-closed sockets.
            let st = socket.state();
            let dead = matches!(
                st,
                tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing
            );
            let idle = now.duration_since(flow.last_activity) > idle_timeout;
            if dead || idle {
                tcp_to_remove.push(*key);
            }
        }
        for key in tcp_to_remove {
            if let Some(flow) = tcp_flows.remove(&key) {
                flow.upstream_closed.store(true, Ordering::Relaxed);
                drop(flow.guest_to_upstream_tx); // signal proxy EOF
                sockets.remove(flow.handle);
            }
        }

        // 3. Service UDP flows: drain inbound (guest → upstream) by
        //    iterating sockets we registered.
        let mut udp_to_remove: Vec<UdpKey> = Vec::new();
        for (key, flow) in udp_flows.iter_mut() {
            // Find the udp::Socket bound to (key.dst_ip, key.dst_port).
            // We stored handle inside flow via UdpFlow, but for simplicity
            // we keep a single shared udp::Socket per key — looked up
            // through the registry below.
            // Idle GC.
            if now.duration_since(flow.last_activity) > idle_timeout {
                udp_to_remove.push(*key);
            }
        }
        for key in udp_to_remove {
            if let Some(flow) = udp_flows.remove(&key) {
                flow.shutdown.store(true, Ordering::Relaxed);
            }
        }

        // 4. Sleep briefly. We could do precise iface.poll_at()-based
        //    timing but a fixed 5ms is fine for our throughput target.
        thread::sleep(Duration::from_millis(5));
    }

    drop(writer);
    Ok(())
}

// ─── Listener registration ───────────────────────────────────────────────────

/// Inspect an inbound Ethernet frame; if it's a TCP SYN to a (dst_ip, dst_port)
/// for which we have no listener, allocate a smoltcp socket in Listen state
/// and spawn the upstream proxy thread. UDP datagrams behave similarly.
fn inspect_and_register(
    frame: &[u8],
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    tx_out_tx: &chan::Sender<Vec<u8>>,
) {
    let eth = match EthernetFrame::new_checked(frame) {
        Ok(e) => e,
        Err(_) => return,
    };
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return;
    }
    let ipv4 = match Ipv4Packet::new_checked(eth.payload()) {
        Ok(p) => p,
        Err(_) => return,
    };
    let src_ip = ipv4.src_addr();
    let dst_ip = ipv4.dst_addr();

    match ipv4.next_header() {
        IpProtocol::Tcp => {
            let tcp = match TcpPacket::new_checked(ipv4.payload()) {
                Ok(p) => p,
                Err(_) => return,
            };
            let key = TcpKey {
                src_ip,
                src_port: tcp.src_port(),
                dst_ip,
                dst_port: tcp.dst_port(),
            };
            if !tcp.syn() || tcp.ack() {
                return; // only act on bare SYNs
            }
            if tcp_flows.contains_key(&key) {
                return;
            }
            register_tcp_flow(key, sockets, tcp_flows);
        }
        IpProtocol::Udp => {
            let udp = match UdpPacket::new_checked(ipv4.payload()) {
                Ok(p) => p,
                Err(_) => return,
            };
            let key = UdpKey {
                src_ip,
                src_port: udp.src_port(),
                dst_ip,
                dst_port: udp.dst_port(),
            };
            if udp_flows.contains_key(&key) {
                return;
            }
            register_udp_flow(key, sockets, udp_flows, tx_out_tx);
        }
        _ => {}
    }
}

fn register_tcp_flow(
    key: TcpKey,
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
) {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    let listen_ep = IpListenEndpoint {
        addr: Some(IpAddress::Ipv4(key.dst_ip)),
        port: key.dst_port,
    };
    if let Err(e) = sock.listen(listen_ep) {
        eprintln!("[netstack] tcp listen {:?}: {e}", listen_ep);
        return;
    }
    sock.set_nagle_enabled(false);
    sock.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    let handle = sockets.add(sock);

    let (u2g_tx, u2g_rx) = chan::bounded::<Vec<u8>>(64);
    let (g2u_tx, g2u_rx) = chan::bounded::<Vec<u8>>(64);
    let upstream_closed = Arc::new(AtomicBool::new(false));
    let upstream_closed2 = Arc::clone(&upstream_closed);

    // Spawn upstream proxy. It blocks on connect, then bridges bytes.
    let dst = SocketAddr::new(IpAddr::V4(ipv4_to_std(key.dst_ip)), key.dst_port);
    thread::Builder::new()
        .name(format!("net-tcp-{}-{}", key.dst_ip, key.dst_port))
        .spawn(move || tcp_proxy(dst, u2g_tx, g2u_rx, upstream_closed2))
        .ok();

    tcp_flows.insert(
        key,
        TcpFlow {
            handle,
            upstream_to_guest_rx: u2g_rx,
            guest_to_upstream_tx: g2u_tx,
            upstream_closed,
            last_activity: Instant::now(),
            closed: false,
        },
    );
    eprintln!("[netstack] tcp flow opened {} → {}", key.src_port, dst);
}

fn tcp_proxy(
    dst: SocketAddr,
    u2g_tx: chan::Sender<Vec<u8>>,
    g2u_rx: chan::Receiver<Vec<u8>>,
    upstream_closed: Arc<AtomicBool>,
) {
    let mut up = match TcpStream::connect_timeout(&dst, Duration::from_secs(8)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[netstack] connect {} fail: {}", dst, e);
            upstream_closed.store(true, Ordering::Relaxed);
            return;
        }
    };
    let _ = up.set_nodelay(true);
    let _ = up.set_read_timeout(Some(Duration::from_millis(200)));

    // Spawn writer pumping g2u_rx → upstream.
    let mut up_w = match up.try_clone() {
        Ok(w) => w,
        Err(_) => {
            upstream_closed.store(true, Ordering::Relaxed);
            return;
        }
    };
    let upstream_closed_w = Arc::clone(&upstream_closed);
    let writer = thread::Builder::new()
        .name(format!("net-tcp-w-{}", dst))
        .spawn(move || {
            while let Ok(buf) = g2u_rx.recv() {
                if up_w.write_all(&buf).is_err() {
                    break;
                }
            }
            let _ = up_w.shutdown(std::net::Shutdown::Write);
            upstream_closed_w.store(true, Ordering::Relaxed);
        })
        .ok();

    // Reader: upstream → u2g_tx.
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match up.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if u2g_tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                if upstream_closed.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        }
    }
    upstream_closed.store(true, Ordering::Relaxed);
    if let Some(j) = writer {
        let _ = j.join();
    }
}

fn register_udp_flow(
    key: UdpKey,
    _sockets: &mut SocketSet<'_>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    tx_out_tx: &chan::Sender<Vec<u8>>,
) {
    // Bind a host UdpSocket and spawn a recv thread that wraps replies into
    // outbound IPv4/UDP/Ethernet frames and pushes them via tx_out_tx
    // (bypassing smoltcp — we craft frames manually because smoltcp's
    // udp::Socket would need any_ip + listen on dst which is awkward).
    let upstream = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[netstack] udp bind: {}", e);
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_millis(500)));
    let upstream = Arc::new(upstream);
    let dst = SocketAddr::new(IpAddr::V4(ipv4_to_std(key.dst_ip)), key.dst_port);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_t = Arc::clone(&shutdown);
    let upstream_t = Arc::clone(&upstream);
    let tx_out = tx_out_tx.clone();

    let join = thread::Builder::new()
        .name(format!("net-udp-{}-{}", key.dst_ip, key.dst_port))
        .spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            while !shutdown_t.load(Ordering::Relaxed) {
                match upstream_t.recv_from(&mut buf) {
                    Ok((n, _from)) => {
                        let frame = build_udp_reply(&buf[..n], &key);
                        let _ = tx_out.send(frame);
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        })
        .expect("spawn udp recv thread");

    udp_flows.insert(
        key,
        UdpFlow {
            upstream,
            dst,
            last_activity: Instant::now(),
            shutdown,
            _join: join,
        },
    );

    eprintln!("[netstack] udp flow opened {}:{} → {}", key.src_ip, key.src_port, dst);
}

/// Build a complete Ethernet/IPv4/UDP frame carrying `payload` from the
/// gateway back to the guest, swapping the original 5-tuple.
fn build_udp_reply(payload: &[u8], key: &UdpKey) -> Vec<u8> {
    use smoltcp::wire::{EthernetFrame as EF, Ipv4Packet as IP, UdpPacket as UP};
    let udp_total = 8 + payload.len();
    let ip_total = 20 + udp_total;
    let eth_total = 14 + ip_total;
    let mut buf = vec![0u8; eth_total];

    // Ethernet
    {
        let mut eth = EF::new_unchecked(&mut buf);
        eth.set_dst_addr(EthernetAddress(GUEST_MAC));
        eth.set_src_addr(EthernetAddress(HOST_MAC));
        eth.set_ethertype(EthernetProtocol::Ipv4);
    }
    // IPv4
    {
        let mut ip = IP::new_unchecked(&mut buf[14..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_len(ip_total as u16);
        ip.set_ident(rand_u16());
        ip.clear_flags();
        ip.set_dont_frag(true);
        ip.set_frag_offset(0);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(key.dst_ip);
        ip.set_dst_addr(key.src_ip);
        ip.fill_checksum();
    }
    // UDP
    {
        let mut udp = UP::new_unchecked(&mut buf[14 + 20..]);
        udp.set_src_port(key.dst_port);
        udp.set_dst_port(key.src_port);
        udp.set_len(udp_total as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&IpAddress::Ipv4(key.dst_ip), &IpAddress::Ipv4(key.src_ip));
    }
    buf
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn smol_now() -> SmolInstant {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let e = EPOCH.get_or_init(Instant::now);
    SmolInstant::from_millis(e.elapsed().as_millis() as i64)
}

fn rand_seed() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

fn rand_u16() -> u16 {
    rand_seed() as u16
}

fn ipv4_to_std(a: Ipv4Address) -> Ipv4Addr {
    let o = a.octets();
    Ipv4Addr::new(o[0], o[1], o[2], o[3])
}
