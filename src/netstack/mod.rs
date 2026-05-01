//! Userspace network stack — replaces in-kernel NAT for `NetworkPolicy::AllowAll`
//! across Windows (HCS micro-VM via HvSocket) and macOS (Virtualization.framework
//! via AF_VSOCK). Linux uses host-shared netns instead, so this module is
//! unused there.
//!
//! Architecture:
//!
//! ```text
//!   Guest tk0 (TUN, 192.168.127.2/24, gw .1)
//!     ↕ length-prefixed Ethernet frames over a duplex stream socket
//!   Host gateway smoltcp Interface (192.168.127.1/24, any_ip=true)
//!     - per-flow TCP socket created on demand on first SYN
//!     - upstream connect via std::net::TcpStream
//!     - per-flow UDP socket created on demand on first datagram
//!     - upstream send/recv via std::net::UdpSocket
//!     - ICMPv4/v6 echo proxied via OS-specific helpers (icmp::send_echo*)
//! ```
//!
//! Wire framing on the underlying duplex stream: `u16-be length || ethernet
//! frame`. Matches the framing the guest-side `tokimo-tun-pump` uses.

#![cfg(any(target_os = "windows", target_os = "macos"))]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel as chan;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet,
    Icmpv6Repr, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpPacket, UdpPacket,
};

mod icmp;

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
/// MTU advertised on the gateway interface.
pub const MTU: usize = 1400;

// IPv6 topology — ULA addresses; guest gets v6 default route via HOST_IP6.
pub const HOST_IP6: Ipv6Address = Ipv6Address::new(0xfd00, 0x007f, 0, 0, 0, 0, 0, 0x0001);
#[allow(dead_code)]
pub const GUEST_IP6: Ipv6Address = Ipv6Address::new(0xfd00, 0x007f, 0, 0, 0, 0, 0, 0x0002);
pub const SUBNET6_PREFIX: u8 = 64;

// ─── Stream-backed Device ────────────────────────────────────────────────────

struct StreamDevice {
    rx: chan::Receiver<Vec<u8>>,
    tx: chan::Sender<Vec<u8>>,
}

struct StreamRxToken(Vec<u8>);
struct StreamTxToken(chan::Sender<Vec<u8>>);

impl RxToken for StreamRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for StreamTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
        r
    }
}

impl Device for StreamDevice {
    type RxToken<'a> = StreamRxToken;
    type TxToken<'a> = StreamTxToken;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx
            .try_recv()
            .ok()
            .map(|frame| (StreamRxToken(frame), StreamTxToken(self.tx.clone())))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(StreamTxToken(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU + 14; // + Ethernet header
        caps
    }
}

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
    src_ip: IpAddress,
    src_port: u16,
    dst_ip: IpAddress,
    dst_port: u16,
}

struct TcpFlow {
    handle: SocketHandle,
    upstream_to_guest_rx: chan::Receiver<Vec<u8>>,
    guest_to_upstream_tx: chan::Sender<Vec<u8>>,
    upstream_closed: Arc<AtomicBool>,
    last_activity: Instant,
    closed: bool,
}

/// State for one upstream UDP flow (keyed by destination port).
///
/// Each destination port gets a smoltcp `udp::Socket` that intercepts guest
/// traffic, plus a real `UdpSocket` for upstream. Reply Ethernet frames are
/// built manually (bypassing smoltcp ARP resolution which has no neighbor
/// entry for the guest — TCP populates it via SYN/SYN-ACK, but UDP doesn't).
struct UdpFlow {
    sock_handle: SocketHandle,
    upstream: UdpSocket,
    /// Last guest endpoint that sent to this port (for routing replies back).
    remote: smoltcp::wire::IpEndpoint,
    /// Destination IP the guest was talking to (used as src IP in replies).
    dst_ip: IpAddress,
    last_activity: Instant,
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Spawn the netstack on a fresh thread bound to the given duplex stream.
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
    let (rx_in_tx, rx_in_rx) = chan::bounded::<Vec<u8>>(256);
    let (tx_out_tx, tx_out_rx) = chan::bounded::<Vec<u8>>(256);

    let shutdown_r = Arc::clone(&shutdown);
    thread::Builder::new().name("netstack-rx".into()).spawn(move || {
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
    thread::Builder::new().name("netstack-tx".into()).spawn(move || {
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

    let mut device = StreamDevice {
        rx: rx_in_rx.clone(),
        tx: tx_out_tx.clone(),
    };
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(HOST_MAC)));
    config.random_seed = rand_seed();
    let mut iface = Interface::new(config, &mut device, smol_now());
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::Ipv4(HOST_IP), SUBNET_PREFIX)).ok();
        addrs.push(IpCidr::new(IpAddress::Ipv6(HOST_IP6), SUBNET6_PREFIX)).ok();
    });
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_flows: HashMap<TcpKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<u16, UdpFlow> = HashMap::new();

    eprintln!(
        "[netstack] gateway {}/{} [v6 {}/{}] ↔ guest {}/{} ready",
        HOST_IP, SUBNET_PREFIX, HOST_IP6, SUBNET6_PREFIX, GUEST_IP, SUBNET_PREFIX
    );

    let idle_timeout = Duration::from_secs(120);

    while !shutdown.load(Ordering::Relaxed) {
        let mut staged: Vec<Vec<u8>> = Vec::new();
        while let Ok(frame) = rx_in_rx.try_recv() {
            inspect_and_register(&frame, &mut sockets, &mut tcp_flows, &mut udp_flows, &tx_out_tx);
            staged.push(frame);
        }
        if !staged.is_empty() {
            let (re_tx, re_rx) = chan::unbounded::<Vec<u8>>();
            for f in staged.drain(..) {
                let _ = re_tx.send(f);
            }
            let mut burst_dev = StreamDevice {
                rx: re_rx,
                tx: tx_out_tx.clone(),
            };
            loop {
                use smoltcp::iface::PollResult;
                match iface.poll(smol_now(), &mut burst_dev, &mut sockets) {
                    PollResult::SocketStateChanged => continue,
                    PollResult::None => break,
                }
            }
        } else {
            iface.poll(smol_now(), &mut device, &mut sockets);
        }

        let now = Instant::now();
        let mut tcp_to_remove: Vec<TcpKey> = Vec::new();
        for (key, flow) in tcp_flows.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
            if socket.can_recv() {
                let _ = socket.recv(|buf| {
                    if !buf.is_empty() {
                        let _ = flow.guest_to_upstream_tx.send(buf.to_vec());
                        flow.last_activity = now;
                    }
                    (buf.len(), ())
                });
            }
            while let Ok(buf) = flow.upstream_to_guest_rx.try_recv() {
                let mut off = 0;
                while off < buf.len() {
                    match socket.send_slice(&buf[off..]) {
                        Ok(0) => break,
                        Ok(n) => off += n,
                        Err(_) => break,
                    }
                }
                flow.last_activity = now;
            }
            if flow.upstream_closed.load(Ordering::Relaxed) && !flow.closed {
                socket.close();
                flow.closed = true;
            }
            let st = socket.state();
            let dead = matches!(st, tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing);
            let idle = now.duration_since(flow.last_activity) > idle_timeout;
            if dead || idle {
                tcp_to_remove.push(*key);
            }
        }
        for key in tcp_to_remove {
            if let Some(flow) = tcp_flows.remove(&key) {
                flow.upstream_closed.store(true, Ordering::Relaxed);
                drop(flow.guest_to_upstream_tx);
                sockets.remove(flow.handle);
            }
        }

        // 3. Service UDP flows: forward guest ↔ upstream via smoltcp sockets.
        let mut udp_to_remove: Vec<u16> = Vec::new();
        for (&port, flow) in udp_flows.iter_mut() {
            let sock = sockets.get_mut::<udp::Socket>(flow.sock_handle);

            // Guest → upstream: drain smoltcp recv buffer, forward to real server.
            if sock.can_recv() {
                while let Ok((data, meta)) = sock.recv() {
                    let dst_ip = meta.local_address.unwrap_or(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
                    let dst = SocketAddr::new(ipaddr_to_std(dst_ip), port);
                    let _ = flow.upstream.send_to(data, dst);
                    flow.remote = meta.endpoint;
                    flow.last_activity = now;
                }
            }

            // Upstream → guest: non-blocking recv, build Ethernet frame
            // manually (bypasses smoltcp ARP resolution, same as ICMP).
            let mut buf = vec![0u8; 2048];
            loop {
                match flow.upstream.recv_from(&mut buf) {
                    Ok((n, _from)) => {
                        // Reply: from upstream (dst_ip the guest spoke to) → guest (flow.remote).
                        match (flow.dst_ip, flow.remote.addr) {
                            (IpAddress::Ipv4(s), IpAddress::Ipv4(d)) => {
                                let frame = build_udp_reply_ethernet_frame_v4(
                                    &s.octets(),
                                    &d.octets(),
                                    port,
                                    flow.remote.port,
                                    &buf[..n],
                                );
                                let _ = tx_out_tx.send(frame);
                                flow.last_activity = now;
                            }
                            (IpAddress::Ipv6(s), IpAddress::Ipv6(d)) => {
                                let frame = build_udp_reply_ethernet_frame_v6(
                                    &s.octets(),
                                    &d.octets(),
                                    port,
                                    flow.remote.port,
                                    &buf[..n],
                                );
                                let _ = tx_out_tx.send(frame);
                                flow.last_activity = now;
                            }
                            _ => break,
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => {
                        udp_to_remove.push(port);
                        break;
                    }
                }
            }

            if now.duration_since(flow.last_activity) > idle_timeout {
                udp_to_remove.push(port);
            }
        }
        for port in udp_to_remove {
            if let Some(flow) = udp_flows.remove(&port) {
                sockets.remove(flow.sock_handle);
            }
        }

        // 3b. Flush: poll again to transmit any frames queued above.
        {
            use smoltcp::iface::PollResult;
            loop {
                match iface.poll(smol_now(), &mut device, &mut sockets) {
                    PollResult::SocketStateChanged => continue,
                    PollResult::None => break,
                }
            }
        }

        thread::sleep(Duration::from_millis(5));
    }

    drop(writer);
    Ok(())
}

fn inspect_and_register(
    frame: &[u8],
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<u16, UdpFlow>,
    tx_out_tx: &chan::Sender<Vec<u8>>,
) {
    let eth = match EthernetFrame::new_checked(frame) {
        Ok(e) => e,
        Err(_) => return,
    };
    match eth.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4 = match Ipv4Packet::new_checked(eth.payload()) {
                Ok(p) => p,
                Err(_) => return,
            };
            let src_ip = IpAddress::Ipv4(ipv4.src_addr());
            let dst_ip = IpAddress::Ipv4(ipv4.dst_addr());
            dispatch_l4(
                ipv4.next_header(),
                ipv4.payload(),
                src_ip,
                dst_ip,
                sockets,
                tcp_flows,
                udp_flows,
                tx_out_tx,
            );
        }
        EthernetProtocol::Ipv6 => {
            let ipv6 = match Ipv6Packet::new_checked(eth.payload()) {
                Ok(p) => p,
                Err(_) => return,
            };
            let src_ip = IpAddress::Ipv6(ipv6.src_addr());
            let dst_ip = IpAddress::Ipv6(ipv6.dst_addr());
            dispatch_l4(
                ipv6.next_header(),
                ipv6.payload(),
                src_ip,
                dst_ip,
                sockets,
                tcp_flows,
                udp_flows,
                tx_out_tx,
            );
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_l4(
    proto: IpProtocol,
    payload: &[u8],
    src_ip: IpAddress,
    dst_ip: IpAddress,
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<u16, UdpFlow>,
    tx_out_tx: &chan::Sender<Vec<u8>>,
) {
    match proto {
        IpProtocol::Tcp => {
            let tcp = match TcpPacket::new_checked(payload) {
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
                return;
            }
            if tcp_flows.contains_key(&key) {
                return;
            }
            register_tcp_flow(key, sockets, tcp_flows);
        }
        IpProtocol::Udp => {
            let udp = match UdpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(_) => return,
            };
            let dst_port = udp.dst_port();
            let src_port = udp.src_port();
            if let Some(flow) = udp_flows.get_mut(&dst_port) {
                // Existing flow: forward this packet upstream and refresh remote.
                let dst = SocketAddr::new(ipaddr_to_std(dst_ip), dst_port);
                let _ = flow.upstream.send_to(udp.payload(), dst);
                flow.remote = smoltcp::wire::IpEndpoint {
                    addr: src_ip,
                    port: src_port,
                };
                return;
            }
            register_udp_flow(dst_port, dst_ip, src_ip, src_port, sockets, udp_flows, udp.payload());
            let _ = tx_out_tx;
        }
        IpProtocol::Icmp => {
            handle_icmpv4_echo(payload, src_ip, dst_ip, tx_out_tx);
        }
        IpProtocol::Icmpv6 => {
            handle_icmpv6_echo(payload, src_ip, dst_ip, tx_out_tx);
        }
        _ => {}
    }
}

fn register_tcp_flow(key: TcpKey, sockets: &mut SocketSet<'_>, tcp_flows: &mut HashMap<TcpKey, TcpFlow>) {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    let listen_ep = IpListenEndpoint {
        addr: Some(key.dst_ip),
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

    let dst = SocketAddr::new(ipaddr_to_std(key.dst_ip), key.dst_port);
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
    dst_port: u16,
    dst_ip: IpAddress,
    src_ip: IpAddress,
    src_port: u16,
    sockets: &mut SocketSet<'_>,
    udp_flows: &mut HashMap<u16, UdpFlow>,
    initial_payload: &[u8],
) {
    // smoltcp UDP socket bound to dst_port. With any_ip=true, this catches
    // all UDP traffic destined to that port regardless of dst IP.
    let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]);
    let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]);
    let mut sock = udp::Socket::new(rx_buf, tx_buf);
    if let Err(e) = sock.bind(dst_port) {
        eprintln!("[netstack] udp bind port {}: {e}", dst_port);
        return;
    }
    let sock_handle = sockets.add(sock);

    let bind_addr = match dst_ip {
        IpAddress::Ipv4(_) => "0.0.0.0:0",
        IpAddress::Ipv6(_) => "[::]:0",
    };
    let upstream = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[netstack] upstream udp bind: {e}");
            sockets.remove(sock_handle);
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_millis(100)));

    // Forward the initial packet that triggered registration.
    let upstream_dst = SocketAddr::new(ipaddr_to_std(dst_ip), dst_port);
    let _ = upstream.send_to(initial_payload, upstream_dst);

    udp_flows.insert(
        dst_port,
        UdpFlow {
            sock_handle,
            upstream,
            remote: smoltcp::wire::IpEndpoint {
                addr: src_ip,
                port: src_port,
            },
            dst_ip,
            last_activity: Instant::now(),
        },
    );

    eprintln!("[netstack] udp flow opened port {dst_port} → {upstream_dst}");
}

// ─── UDP reply frame builders ───────────────────────────────────────────────
//
// Build complete Ethernet+IP+UDP frames manually, bypassing smoltcp's ARP
// resolution (which has no neighbor entry for the guest — TCP populates it
// via the SYN/SYN-ACK exchange, but UDP has no such handshake).

fn build_udp_reply_ethernet_frame_v4(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_hdr_len = 20usize;
    let udp_hdr_len = 8usize;
    let udp_total = udp_hdr_len + payload.len();
    let ip_total = ip_hdr_len + udp_total;
    let eth_total = 14 + ip_total;
    let mut buf = vec![0u8; eth_total];

    // Ethernet header
    buf[0..6].copy_from_slice(&GUEST_MAC);
    buf[6..12].copy_from_slice(&HOST_MAC);
    buf[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header
    buf[14] = 0x45;
    buf[15] = 0x00;
    buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    buf[18..20].copy_from_slice(&0u16.to_be_bytes());
    buf[20..22].copy_from_slice(&[0x40, 0x00]); // DF
    buf[22] = 64;
    buf[23] = 17; // UDP
    buf[24..26].copy_from_slice(&[0x00, 0x00]);
    buf[26..30].copy_from_slice(src_ip);
    buf[30..34].copy_from_slice(dst_ip);
    let ip_cksum = ip_checksum(&buf[14..14 + ip_hdr_len]);
    buf[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    // UDP header + payload
    let udp_start = 14 + ip_hdr_len;
    buf[udp_start..udp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_start + 2..udp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_total as u16).to_be_bytes());
    buf[udp_start + 6..udp_start + 8].copy_from_slice(&[0x00, 0x00]);
    buf[udp_start + udp_hdr_len..udp_start + udp_hdr_len + payload.len()].copy_from_slice(payload);
    let udp_cksum = udp_checksum_v4(src_ip, dst_ip, &buf[udp_start..udp_start + udp_total]);
    buf[udp_start + 6..udp_start + 8].copy_from_slice(&udp_cksum.to_be_bytes());

    buf
}

fn build_udp_reply_ethernet_frame_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_hdr_len = 40usize;
    let udp_hdr_len = 8usize;
    let udp_total = udp_hdr_len + payload.len();
    let ip_total = ip_hdr_len + udp_total;
    let eth_total = 14 + ip_total;
    let mut buf = vec![0u8; eth_total];

    // Ethernet header
    buf[0..6].copy_from_slice(&GUEST_MAC);
    buf[6..12].copy_from_slice(&HOST_MAC);
    buf[12..14].copy_from_slice(&[0x86, 0xdd]); // IPv6

    // IPv6 header (40 bytes)
    buf[14] = 0x60; // version=6, traffic class hi nibble = 0
    buf[15] = 0x00;
    buf[16..18].copy_from_slice(&[0x00, 0x00]); // flow label tail
    buf[18..20].copy_from_slice(&(udp_total as u16).to_be_bytes()); // payload length
    buf[20] = 17; // next header = UDP
    buf[21] = 64; // hop limit
    buf[22..38].copy_from_slice(src_ip);
    buf[38..54].copy_from_slice(dst_ip);

    // UDP header + payload
    let udp_start = 14 + ip_hdr_len;
    buf[udp_start..udp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_start + 2..udp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_total as u16).to_be_bytes());
    buf[udp_start + 6..udp_start + 8].copy_from_slice(&[0x00, 0x00]);
    buf[udp_start + udp_hdr_len..udp_start + udp_hdr_len + payload.len()].copy_from_slice(payload);
    let udp_cksum = udp_checksum_v6(src_ip, dst_ip, &buf[udp_start..udp_start + udp_total]);
    buf[udp_start + 6..udp_start + 8].copy_from_slice(&udp_cksum.to_be_bytes());

    buf
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum_v4(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_segment: &[u8]) -> u16 {
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32; // protocol
    sum += udp_len as u32;
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 { 0xFFFF } else { cksum }
}

fn udp_checksum_v6(src_ip: &[u8; 16], dst_ip: &[u8; 16], udp_segment: &[u8]) -> u16 {
    let udp_len = udp_segment.len() as u32;
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < 16 {
        sum += u16::from_be_bytes([src_ip[i], src_ip[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]) as u32;
        i += 2;
    }
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;
    sum += 17u32; // next header = UDP
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 { 0xFFFF } else { cksum }
}

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

fn ipv6_to_std(a: Ipv6Address) -> Ipv6Addr {
    Ipv6Addr::from(a.octets())
}

fn ipaddr_to_std(a: IpAddress) -> IpAddr {
    match a {
        IpAddress::Ipv4(v4) => IpAddr::V4(ipv4_to_std(v4)),
        IpAddress::Ipv6(v6) => IpAddr::V6(ipv6_to_std(v6)),
    }
}

// ─── ICMP echo proxy ────────────────────────────────────────────────────────
//
// Strategy: parse guest EchoRequest, spawn a worker that uses an
// OS-specific helper (Win32 IcmpSendEcho on Windows; SOCK_DGRAM
// IPPROTO_ICMP on macOS) to ping upstream, then fabricate an EchoReply
// preserving identifier+sequence+payload back to the guest.

fn handle_icmpv4_echo(payload: &[u8], src_ip: IpAddress, dst_ip: IpAddress, tx_out_tx: &chan::Sender<Vec<u8>>) {
    let icmp = match Icmpv4Packet::new_checked(payload) {
        Ok(p) => p,
        Err(_) => return,
    };
    let repr = match Icmpv4Repr::parse(&icmp, &smoltcp::phy::ChecksumCapabilities::default()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let (ident, seq, data) = match repr {
        Icmpv4Repr::EchoRequest { ident, seq_no, data } => (ident, seq_no, data.to_vec()),
        _ => return,
    };
    let (src, dst) = match (src_ip, dst_ip) {
        (IpAddress::Ipv4(s), IpAddress::Ipv4(d)) => (s, d),
        _ => return,
    };
    let tx = tx_out_tx.clone();
    thread::Builder::new()
        .name(format!("net-icmp4-{}", dst))
        .spawn(move || {
            let ok = icmp::send_echo_v4(ipv4_to_std(dst), &data, Duration::from_secs(4));
            if ok {
                let frame = build_icmpv4_echo_reply(dst, src, ident, seq, &data);
                let _ = tx.send(frame);
            }
        })
        .ok();
}

fn handle_icmpv6_echo(payload: &[u8], src_ip: IpAddress, dst_ip: IpAddress, tx_out_tx: &chan::Sender<Vec<u8>>) {
    let icmp = match Icmpv6Packet::new_checked(payload) {
        Ok(p) => p,
        Err(_) => return,
    };
    let (src, dst) = match (src_ip, dst_ip) {
        (IpAddress::Ipv6(s), IpAddress::Ipv6(d)) => (s, d),
        _ => return,
    };
    let repr = match Icmpv6Repr::parse(&src, &dst, &icmp, &smoltcp::phy::ChecksumCapabilities::default()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let (ident, seq, data) = match repr {
        Icmpv6Repr::EchoRequest { ident, seq_no, data } => (ident, seq_no, data.to_vec()),
        _ => return,
    };
    let tx = tx_out_tx.clone();
    thread::Builder::new()
        .name(format!("net-icmp6-{}", dst))
        .spawn(move || {
            let ok = icmp::send_echo_v6(ipv6_to_std(dst), &data, Duration::from_secs(4));
            if ok {
                let frame = build_icmpv6_echo_reply(dst, src, ident, seq, &data);
                let _ = tx.send(frame);
            }
        })
        .ok();
}

fn build_icmpv4_echo_reply(src: Ipv4Address, dst: Ipv4Address, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    use smoltcp::wire::{EthernetFrame as EF, Ipv4Packet as IP};
    let icmp_total = 8 + data.len();
    let ip_total = 20 + icmp_total;
    let eth_total = 14 + ip_total;
    let mut buf = vec![0u8; eth_total];

    {
        let mut eth = EF::new_unchecked(&mut buf);
        eth.set_dst_addr(EthernetAddress(GUEST_MAC));
        eth.set_src_addr(EthernetAddress(HOST_MAC));
        eth.set_ethertype(EthernetProtocol::Ipv4);
    }
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
        ip.set_next_header(IpProtocol::Icmp);
        ip.set_src_addr(src);
        ip.set_dst_addr(dst);
        ip.fill_checksum();
    }
    {
        let mut icmp = Icmpv4Packet::new_unchecked(&mut buf[14 + 20..]);
        let repr = Icmpv4Repr::EchoReply {
            ident,
            seq_no: seq,
            data,
        };
        repr.emit(&mut icmp, &smoltcp::phy::ChecksumCapabilities::default());
    }
    buf
}

fn build_icmpv6_echo_reply(src: Ipv6Address, dst: Ipv6Address, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    use smoltcp::wire::{EthernetFrame as EF, Ipv6Packet as IP};
    let icmp_total = 8 + data.len();
    let ip_total = 40 + icmp_total;
    let eth_total = 14 + ip_total;
    let mut buf = vec![0u8; eth_total];

    {
        let mut eth = EF::new_unchecked(&mut buf);
        eth.set_dst_addr(EthernetAddress(GUEST_MAC));
        eth.set_src_addr(EthernetAddress(HOST_MAC));
        eth.set_ethertype(EthernetProtocol::Ipv6);
    }
    {
        let mut ip = IP::new_unchecked(&mut buf[14..]);
        ip.set_version(6);
        ip.set_traffic_class(0);
        ip.set_flow_label(0);
        ip.set_payload_len(icmp_total as u16);
        ip.set_next_header(IpProtocol::Icmpv6);
        ip.set_hop_limit(64);
        ip.set_src_addr(src);
        ip.set_dst_addr(dst);
    }
    {
        let mut icmp = Icmpv6Packet::new_unchecked(&mut buf[14 + 40..]);
        let repr = Icmpv6Repr::EchoReply {
            ident,
            seq_no: seq,
            data,
        };
        repr.emit(&src, &dst, &mut icmp, &smoltcp::phy::ChecksumCapabilities::default());
    }
    buf
}
