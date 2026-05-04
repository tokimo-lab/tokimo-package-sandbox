//! Userspace network stack — always-on TCP/UDP/ICMP gateway between the
//! sandboxed guest and the host process. Used by all three platforms
//! (`Linux` via `socketpair(STREAM)` through bwrap; `macOS` via
//! virtio-vsock; `Windows` via HvSocket).
//!
//! Architecture:
//!
//! ```text
//!   Guest tk0 (TUN, 192.168.127.2/24, gw .1)
//!     ↕ length-prefixed Ethernet frames over a duplex stream socket
//!   Host gateway smoltcp Interface (192.168.127.1/24, any_ip=true)
//!     - per-flow TCP socket created on demand on first SYN
//!     - per-flow UDP socket created on demand on first datagram
//!     - ICMPv4/v6 echo proxied via OS-specific helpers (icmp::send_echo*)
//! ```
//!
//! ## Policy
//!
//! The gateway is always running, even under `NetworkPolicy::Blocked`.
//! `EgressPolicy` controls whether non-local-service flows are forwarded
//! to the host kernel:
//!
//! - `AllowAll`: any guest TCP/UDP connect attempts to dial the original
//!   destination via `std::net::TcpStream` / `UdpSocket`.
//! - `Blocked`: only flows whose destination matches a registered
//!   `LocalService` are spliced through; everything else is dropped (TCP
//!   socket is never accepted → guest sees RST; UDP packets never get an
//!   upstream socket; ICMP echo replies are not generated).
//!
//! ## Local services
//!
//! A `LocalService` redirects guest traffic destined to
//! `(HOST_IP|HOST_IP6, port)` to a kernel-side `SocketAddr` (typically
//! `127.0.0.1:N`). This is how the macOS backend exposes its in-process
//! NFSv3 server to the guest while keeping `EgressPolicy::Blocked` enforced
//! for everything else.
//!
//! Wire framing on the underlying duplex stream: `u16-be length || ethernet
//! frame`. Matches what the guest-side `tokimo-tun-pump` produces.

#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel as chan;
use mio::net::{TcpStream as MioTcpStream, UdpSocket as MioUdpSocket};
use mio::{Events, Interest, Poll, Token, Waker};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet,
    Icmpv6Repr, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpPacket, UdpPacket,
};

mod host_dns;
mod icmp;

// ─── Topology constants ──────────────────────────────────────────────────────
//
// These are all derived from `crate::net_constants`, which is the single
// source of truth shared with the guest-side pumps. The smoltcp-typed
// re-exports below are kept because the rest of this module's code uses
// smoltcp wire types directly.

use crate::net_constants;

/// Gateway (host) IP — what the guest sets as default route.
pub const HOST_IP: Ipv4Address = Ipv4Address::new(
    net_constants::HOST_IP4_OCTETS[0],
    net_constants::HOST_IP4_OCTETS[1],
    net_constants::HOST_IP4_OCTETS[2],
    net_constants::HOST_IP4_OCTETS[3],
);
/// Guest IP — assigned to the guest TUN interface by `init.sh`.
pub const GUEST_IP: Ipv4Address = Ipv4Address::new(
    net_constants::GUEST_IP4_OCTETS[0],
    net_constants::GUEST_IP4_OCTETS[1],
    net_constants::GUEST_IP4_OCTETS[2],
    net_constants::GUEST_IP4_OCTETS[3],
);
/// Subnet prefix length.
pub const SUBNET_PREFIX: u8 = net_constants::SUBNET4_PREFIX;
/// Gateway MAC — synthetic, picked outside the IANA OUI space.
pub const HOST_MAC: [u8; 6] = net_constants::HOST_MAC;
/// Guest MAC — must match the MAC `tokimo-tun-pump` programs into tk0.
pub const GUEST_MAC: [u8; 6] = net_constants::GUEST_MAC;
/// MTU advertised on the gateway interface.
pub const MTU: usize = net_constants::MTU;

// IPv6 topology — ULA addresses; guest gets v6 default route via HOST_IP6.
pub const HOST_IP6: Ipv6Address = Ipv6Address::new(
    net_constants::HOST_IP6_SEGMENTS[0],
    net_constants::HOST_IP6_SEGMENTS[1],
    net_constants::HOST_IP6_SEGMENTS[2],
    net_constants::HOST_IP6_SEGMENTS[3],
    net_constants::HOST_IP6_SEGMENTS[4],
    net_constants::HOST_IP6_SEGMENTS[5],
    net_constants::HOST_IP6_SEGMENTS[6],
    net_constants::HOST_IP6_SEGMENTS[7],
);
#[allow(dead_code)]
pub const GUEST_IP6: Ipv6Address = Ipv6Address::new(
    net_constants::GUEST_IP6_SEGMENTS[0],
    net_constants::GUEST_IP6_SEGMENTS[1],
    net_constants::GUEST_IP6_SEGMENTS[2],
    net_constants::GUEST_IP6_SEGMENTS[3],
    net_constants::GUEST_IP6_SEGMENTS[4],
    net_constants::GUEST_IP6_SEGMENTS[5],
    net_constants::GUEST_IP6_SEGMENTS[6],
    net_constants::GUEST_IP6_SEGMENTS[7],
);
pub const SUBNET6_PREFIX: u8 = net_constants::SUBNET6_PREFIX;

// ─── Egress policy & local-service routing ──────────────────────────────

/// Whether non-local-service flows are forwarded to the host kernel.
/// Independent of `LocalService` registration: a `Blocked` gateway with
/// registered local services still routes those services, only the
/// arbitrary-destination upstream connect path is suppressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressPolicy {
    /// Original behavior: open kernel sockets to the actual L4 destination.
    AllowAll,
    /// Drop everything except registered `LocalService` traffic.
    Blocked,
}

/// Redirect guest traffic destined to `(HOST_IP|HOST_IP6, host_port)` to
/// a kernel-side `SocketAddr`. Used to expose in-process services (NFS,
/// future: docker registry mirror, etc.) to the guest without leaking
/// them onto the host's real network namespace.
#[derive(Clone, Debug)]
pub struct LocalService {
    /// TCP port the guest dials at the gateway IP.
    pub host_port: u16,
    /// Where to splice incoming flows on the host side. Typically
    /// `127.0.0.1:<ephemeral>`.
    pub local_addr: SocketAddr,
}

/// I/O context: mio Registry + per-flow token allocator. Threaded
/// through the dispatch chain so new flows can register their upstream
/// sockets with the main loop's `Poll`.
struct IoCtx<'a> {
    registry: &'a mio::Registry,
    next_token: &'a mut usize,
}

impl IoCtx<'_> {
    fn alloc_token(&mut self) -> Token {
        // Token(0) is reserved for the Waker.
        *self.next_token = self.next_token.wrapping_add(1).max(1);
        Token(*self.next_token)
    }
}

/// Routing context plumbed through the dispatch chain. Cheap to clone
/// (small Vec).
#[derive(Clone, Debug)]
struct RouteCtx {
    egress: EgressPolicy,
    local_services: Vec<LocalService>,
    /// Upstream DNS resolver used to proxy guest queries sent to the
    /// gateway IP on port 53. Discovered at netstack start. `None`
    /// disables DNS proxying (queries to the gateway will time out).
    host_dns: Option<SocketAddr>,
}

impl RouteCtx {
    /// Look up a TCP destination. Returns `Some(addr)` if traffic should be
    /// forwarded (either to the redirected local service or, under
    /// AllowAll, to the original destination). `None` means the flow must
    /// not be registered (Blocked + non-local destination).
    fn resolve_tcp(&self, dst_ip: IpAddress, dst_port: u16) -> Option<SocketAddr> {
        let is_gateway = matches!(dst_ip, IpAddress::Ipv4(ip) if ip == HOST_IP)
            || matches!(dst_ip, IpAddress::Ipv6(ip) if ip == HOST_IP6);
        if is_gateway && let Some(svc) = self.local_services.iter().find(|s| s.host_port == dst_port) {
            return Some(svc.local_addr);
        }
        match self.egress {
            EgressPolicy::AllowAll => Some(SocketAddr::new(ipaddr_to_std(dst_ip), dst_port)),
            EgressPolicy::Blocked => None,
        }
    }

    /// UDP/ICMP have no local-service routing today; only AllowAll
    /// permits upstream forwarding.
    fn allows_upstream(&self) -> bool {
        matches!(self.egress, EgressPolicy::AllowAll)
    }
}

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
    /// Upstream socket, registered with the main `Poll` (READABLE | WRITABLE).
    upstream: MioTcpStream,
    /// Token used to register `upstream` — kept only so we can deregister
    /// on flow removal (mio `Registry::deregister` operates on the source,
    /// the token isn't actually consulted, but we keep it for symmetry
    /// with `UdpFlow` if we ever want a token→flow lookup).
    #[allow(dead_code)]
    token: Token,
    state: TcpUpstreamState,
    /// Bytes read from the guest's smoltcp socket waiting to be written
    /// upstream once the kernel send buffer has room.
    pending_to_upstream: VecDeque<Vec<u8>>,
    /// Bytes read from upstream that did not all fit into the smoltcp TX
    /// buffer last round; the `usize` is the already-written offset.  Must
    /// be flushed before reading more from upstream.
    pending_to_guest: Option<(Vec<u8>, usize)>,
    last_activity: Instant,
    /// True once we have called `socket.close()` to FIN the guest.
    closed: bool,
    /// True once we have called `sock.pause_synack(false)`.
    synack_unpaused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpUpstreamState {
    /// `mio::net::TcpStream::connect` returned; waiting for WRITABLE event
    /// to confirm the kernel finished the 3-way handshake.
    Connecting,
    /// Upstream connected, both halves open.
    Connected,
    /// Upstream sent FIN (read returned 0).  We can still send guest→upstream
    /// data until the guest also FINs; once `pending_to_guest` is drained we
    /// `socket.close()` to relay the FIN to the guest.
    UpstreamFinned,
    /// Connect failed, RST, or fatal I/O error.  Drop the flow.
    Failed,
}

/// State for one upstream UDP flow (keyed by full 4-tuple).
///
/// Each (src_ip, src_port, dst_ip, dst_port) gets its own smoltcp
/// `udp::Socket` and upstream `UdpSocket`.  Reply Ethernet frames are
/// built manually (bypassing smoltcp ARP resolution which has no neighbor
/// entry for the guest — TCP populates it via SYN/SYN-ACK, but UDP doesn't).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    src_ip: IpAddress,
    src_port: u16,
    dst_ip: IpAddress,
    dst_port: u16,
}

struct UdpFlow {
    sock_handle: SocketHandle,
    upstream: MioUdpSocket,
    /// Guest-side sender endpoint (used to address reply Ethernet frames).
    remote: smoltcp::wire::IpEndpoint,
    /// IP family; v4↔v6 replies from wrong family are discarded.
    family_v4: bool,
    last_activity: Instant,
    /// If `Some`, this flow is a guest→gateway:53 DNS proxy: outbound
    /// packets are sent to this resolver instead of the literal gateway IP,
    /// and reply frames spoof their source as the gateway:53 so the guest
    /// resolver accepts them.
    dns_rewrite: Option<SocketAddr>,
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Spawn the netstack on a fresh thread bound to the given duplex stream.
///
/// `egress` controls whether non-local-service flows hit the host kernel.
/// `local_services` registers in-process service redirects (e.g. the
/// macOS NFSv3 server reachable at `192.168.127.1:2049`).
pub fn spawn(
    read_half: Box<dyn Read + Send>,
    write_half: Box<dyn Write + Send>,
    shutdown: Arc<AtomicBool>,
    egress: EgressPolicy,
    local_services: Vec<LocalService>,
) -> thread::JoinHandle<()> {
    let host_dns = host_dns::detect();
    if let Some(d) = host_dns {
        eprintln!("[netstack] host DNS resolver: {d}");
    } else {
        eprintln!("[netstack] no host DNS resolver detected; gateway:53 proxy disabled");
    }
    let ctx = RouteCtx {
        egress,
        local_services,
        host_dns,
    };
    thread::Builder::new()
        .name("tokimo-netstack".into())
        .spawn(move || {
            if let Err(e) = run(read_half, write_half, shutdown, ctx) {
                eprintln!("[netstack] fatal: {e}");
            }
        })
        .expect("spawn netstack thread")
}

fn run(
    mut read_half: Box<dyn Read + Send>,
    write_half: Box<dyn Write + Send>,
    shutdown: Arc<AtomicBool>,
    ctx: RouteCtx,
) -> std::io::Result<()> {
    let (rx_in_tx, rx_in_rx) = chan::bounded::<Vec<u8>>(256);
    let (tx_out_tx, tx_out_rx) = chan::bounded::<Vec<u8>>(256);

    // mio Poll multiplexes upstream UDP sockets + a Waker for "channel got
    // pushed" events (rx_in_rx, tcp upstream→guest channels, tcp ready
    // signals).  This replaces the prior fixed-cap sleep-on-recv_timeout
    // scheme so any upstream readiness wakes the main loop immediately.
    const TOKEN_WAKER: Token = Token(0);
    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), TOKEN_WAKER)?);

    let shutdown_r = Arc::clone(&shutdown);
    let waker_r = Arc::clone(&waker);
    thread::Builder::new().name("netstack-rx".into()).spawn(move || {
        while !shutdown_r.load(Ordering::Relaxed) {
            match read_frame(&mut read_half) {
                Ok(f) => {
                    if rx_in_tx.send(f).is_err() {
                        break;
                    }
                    let _ = waker_r.wake();
                }
                Err(e) => {
                    eprintln!("[netstack-rx] read end: {e}");
                    break;
                }
            }
        }
    })?;

    // Writer thread: blocks on `recv()` until either a frame arrives or all
    // senders are dropped (which is how shutdown propagates — no time-based
    // poll needed). The shared `Mutex<write_half>` is only here so the main
    // function can `drop(writer)` at the end to be sure no other reference
    // outlives the loop; the writer thread itself is the only locker.
    let writer = Arc::new(Mutex::new(write_half));
    let writer_thread = Arc::clone(&writer);
    thread::Builder::new().name("netstack-tx".into()).spawn(move || {
        while let Ok(frame) = tx_out_rx.recv() {
            let mut w = writer_thread.lock().unwrap();
            if let Err(e) = write_frame(&mut *w, &frame) {
                eprintln!("[netstack-tx] write end: {e}");
                break;
            }
        }
    })?;

    // TX-only device after initialisation: the rx side is permanently closed so
    // smoltcp never reads frames directly from the main channel.  All guest RX
    // frames are routed through inspect_and_register → burst_dev instead.
    let (_, dead_rx) = chan::bounded::<Vec<u8>>(0); // sender dropped → always Err
    let mut device = StreamDevice {
        rx: dead_rx,
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
    let mut udp_flows: HashMap<UdpKey, UdpFlow> = HashMap::new();

    eprintln!(
        "[netstack] gateway {}/{} [v6 {}/{}] ↔ guest {}/{} ready (egress={:?}, local_services={})",
        HOST_IP,
        SUBNET_PREFIX,
        HOST_IP6,
        SUBNET6_PREFIX,
        GUEST_IP,
        SUBNET_PREFIX,
        ctx.egress,
        ctx.local_services.len()
    );

    let idle_timeout = Duration::from_secs(120);
    // UDP flows are typically short-lived (DNS, NTP); reap them aggressively
    // so accumulated idle sockets don't slow down the main poll loop.
    let udp_idle_timeout = Duration::from_secs(15);

    let mut events = Events::with_capacity(64);
    let mut next_token: usize = 0;

    while !shutdown.load(Ordering::Relaxed) {
        let mut io = IoCtx {
            registry: poll.registry(),
            next_token: &mut next_token,
        };
        let mut staged: Vec<Vec<u8>> = Vec::new();
        while let Ok(frame) = rx_in_rx.try_recv() {
            inspect_and_register(
                &frame,
                &mut sockets,
                &mut tcp_flows,
                &mut udp_flows,
                &tx_out_tx,
                &ctx,
                &mut io,
            );
            staged.push(frame);
        }
        // Feed staged frames (possibly empty) to smoltcp via a one-shot
        // device.  When staged is empty the channel drains immediately and
        // smoltcp still runs to emit ACKs / retransmits / keepalives.
        {
            let (re_tx, re_rx) = chan::unbounded::<Vec<u8>>();
            for f in staged.drain(..) {
                let _ = re_tx.send(f);
            }
            drop(re_tx); // disconnect → receive() → None once drained
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
        }

        let now = Instant::now();
        let mut tcp_to_remove: Vec<TcpKey> = Vec::new();
        for (key, flow) in tcp_flows.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);

            // Promote Connecting → Connected/Failed once the kernel finishes
            // the handshake. mio fires WRITABLE on first connect completion,
            // but we re-check every iteration so a polling-without-event path
            // (e.g. main loop woken by another flow) still makes progress.
            if flow.state == TcpUpstreamState::Connecting {
                match flow.upstream.take_error() {
                    Ok(Some(_)) | Err(_) => flow.state = TcpUpstreamState::Failed,
                    Ok(None) => match flow.upstream.peer_addr() {
                        Ok(_) => flow.state = TcpUpstreamState::Connected,
                        Err(ref e) if e.kind() == io::ErrorKind::NotConnected => {}
                        Err(_) => flow.state = TcpUpstreamState::Failed,
                    },
                }
            }

            // Drive SYN-ACK release based on connect outcome.
            if !flow.synack_unpaused {
                match flow.state {
                    TcpUpstreamState::Connected => {
                        socket.pause_synack(false);
                        flow.synack_unpaused = true;
                    }
                    TcpUpstreamState::Failed => {
                        socket.abort();
                        tcp_to_remove.push(*key);
                        continue;
                    }
                    _ => {}
                }
            }

            // Guest → upstream: drain smoltcp recv buffer into pending queue,
            // then flush as much as the kernel will accept (non-blocking).
            // Backpressure: stop pulling from smoltcp once ~256KiB is buffered
            // so smoltcp can shrink the advertised window — same goal as the
            // old `chan::bounded(64).is_full()` check.
            let pending_bytes: usize = flow.pending_to_upstream.iter().map(|b| b.len()).sum();
            if matches!(
                flow.state,
                TcpUpstreamState::Connected | TcpUpstreamState::UpstreamFinned
            ) && socket.can_recv()
                && pending_bytes < 256 * 1024
            {
                let _ = socket.recv(|buf| {
                    if !buf.is_empty() {
                        flow.pending_to_upstream.push_back(buf.to_vec());
                        flow.last_activity = now;
                    }
                    (buf.len(), ())
                });
            }
            while let Some(front) = flow.pending_to_upstream.front_mut() {
                match flow.upstream.write(front) {
                    Ok(0) => break,
                    Ok(n) if n == front.len() => {
                        flow.pending_to_upstream.pop_front();
                        flow.last_activity = now;
                    }
                    Ok(n) => {
                        front.drain(..n);
                        flow.last_activity = now;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        flow.state = TcpUpstreamState::Failed;
                        break;
                    }
                }
            }
            // If guest has FIN'd (smoltcp socket transitioned past Established
            // into the close states) and we've drained all pending bytes,
            // shut down the upstream write side so the peer sees EOF.
            if flow.pending_to_upstream.is_empty()
                && matches!(
                    socket.state(),
                    tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::Closed
                )
            {
                let _ = flow.upstream.shutdown(std::net::Shutdown::Write);
            }

            // Upstream → guest: flush any leftover bytes first, then read
            // more from the kernel (also non-blocking, edge-triggered drain).
            let still_pending = if let Some((buf, off)) = &mut flow.pending_to_guest {
                match socket.send_slice(&buf[*off..]) {
                    Ok(0) | Err(_) => true,
                    Ok(n) => {
                        *off += n;
                        flow.last_activity = now;
                        *off < buf.len()
                    }
                }
            } else {
                false
            };
            if !still_pending {
                flow.pending_to_guest = None;
                if matches!(flow.state, TcpUpstreamState::Connected) {
                    let mut up_buf = vec![0u8; 32 * 1024];
                    loop {
                        if !socket.can_send() {
                            break;
                        }
                        match flow.upstream.read(&mut up_buf) {
                            Ok(0) => {
                                flow.state = TcpUpstreamState::UpstreamFinned;
                                break;
                            }
                            Ok(n) => {
                                let data = up_buf[..n].to_vec();
                                let mut off = 0;
                                while off < data.len() {
                                    match socket.send_slice(&data[off..]) {
                                        Ok(0) | Err(_) => {
                                            flow.pending_to_guest = Some((data, off));
                                            break;
                                        }
                                        Ok(m) => off += m,
                                    }
                                }
                                if flow.pending_to_guest.is_some() {
                                    break;
                                }
                                flow.last_activity = now;
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => {
                                flow.state = TcpUpstreamState::Failed;
                                break;
                            }
                        }
                    }
                }
            }

            // If upstream has fully closed and we've drained all bytes to the
            // guest, FIN the guest side.
            if matches!(flow.state, TcpUpstreamState::UpstreamFinned | TcpUpstreamState::Failed)
                && flow.pending_to_guest.is_none()
                && !flow.closed
            {
                socket.close();
                flow.closed = true;
            }
            let st = socket.state();
            let upstream_done = matches!(flow.state, TcpUpstreamState::UpstreamFinned | TcpUpstreamState::Failed);
            let dead = matches!(st, tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing)
                || (upstream_done && matches!(st, tcp::State::FinWait1 | tcp::State::FinWait2 | tcp::State::LastAck));
            let idle = now.duration_since(flow.last_activity) > idle_timeout;
            if dead || idle {
                tcp_to_remove.push(*key);
            }
        }
        for key in tcp_to_remove {
            if let Some(mut flow) = tcp_flows.remove(&key) {
                let _ = poll.registry().deregister(&mut flow.upstream);
                sockets.remove(flow.handle);
            }
        }

        // 3. Service UDP flows: forward guest ↔ upstream via smoltcp sockets.
        let mut udp_to_remove: Vec<UdpKey> = Vec::new();
        for (&key, flow) in udp_flows.iter_mut() {
            let sock = sockets.get_mut::<udp::Socket>(flow.sock_handle);

            // Guest → upstream: drain smoltcp recv buffer, forward to real server.
            if sock.can_recv() {
                while let Ok((data, meta)) = sock.recv() {
                    let dst = if let Some(rewrite) = flow.dns_rewrite {
                        rewrite
                    } else {
                        let dst_ip = meta.local_address.unwrap_or(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
                        SocketAddr::new(ipaddr_to_std(dst_ip), key.dst_port)
                    };
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
                    Ok((n, from)) => {
                        // For DNS-proxied flows the guest sent to the gateway,
                        // so the reply must appear to come from the gateway —
                        // not from the real upstream resolver. Otherwise the
                        // guest resolver discards it as a martian response.
                        let (src_ip_addr, src_port) = if flow.dns_rewrite.is_some() {
                            (
                                if flow.family_v4 {
                                    IpAddr::V4(std::net::Ipv4Addr::from(HOST_IP.octets()))
                                } else {
                                    IpAddr::V6(std::net::Ipv6Addr::from(HOST_IP6.octets()))
                                },
                                key.dst_port,
                            )
                        } else {
                            (from.ip(), from.port())
                        };
                        match (src_ip_addr, flow.remote.addr, flow.family_v4) {
                            (IpAddr::V4(s), IpAddress::Ipv4(d), true) => {
                                let frame = build_udp_reply_ethernet_frame_v4(
                                    &s.octets(),
                                    &d.octets(),
                                    src_port,
                                    flow.remote.port,
                                    &buf[..n],
                                );
                                let _ = tx_out_tx.send(frame);
                                flow.last_activity = now;
                            }
                            (IpAddr::V6(s), IpAddress::Ipv6(d), false) => {
                                let frame = build_udp_reply_ethernet_frame_v6(
                                    &s.octets(),
                                    &d.octets(),
                                    src_port,
                                    flow.remote.port,
                                    &buf[..n],
                                );
                                let _ = tx_out_tx.send(frame);
                                flow.last_activity = now;
                            }
                            // Cross-family or mismatched flow record: drop.
                            _ => continue,
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => {
                        udp_to_remove.push(key);
                        break;
                    }
                }
            }

            if now.duration_since(flow.last_activity) > udp_idle_timeout {
                udp_to_remove.push(key);
            }
        }
        for key in udp_to_remove {
            if let Some(mut flow) = udp_flows.remove(&key) {
                let _ = poll.registry().deregister(&mut flow.upstream);
                sockets.remove(flow.sock_handle);
            }
        }

        // Wake on any of: a guest frame arrives (rx_in waker), an upstream
        // UDP socket becomes readable (registered tokens), a TCP proxy
        // pushes data or a state change (tcp_proxy waker), or smoltcp's
        // own retransmit/keepalive timer expires.
        let poll_delay = iface
            .poll_delay(smol_now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_secs(1));
        events.clear();
        let _ = poll.poll(&mut events, Some(poll_delay));
    }

    drop(writer);
    Ok(())
}

fn inspect_and_register(
    frame: &[u8],
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    tx_out_tx: &chan::Sender<Vec<u8>>,
    ctx: &RouteCtx,
    io: &mut IoCtx<'_>,
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
                ctx,
                io,
            );
        }
        EthernetProtocol::Ipv6 => {
            let ipv6 = match Ipv6Packet::new_checked(eth.payload()) {
                Ok(p) => p,
                Err(_) => return,
            };
            let src_ip = IpAddress::Ipv6(ipv6.src_addr());
            let dst_ip = IpAddress::Ipv6(ipv6.dst_addr());
            // Walk past any IPv6 extension headers to reach the L4 protocol.
            let (proto, l4_payload) = match skip_ipv6_ext_headers(ipv6.next_header(), ipv6.payload()) {
                Some(v) => v,
                None => return,
            };
            dispatch_l4(
                proto, l4_payload, src_ip, dst_ip, sockets, tcp_flows, udp_flows, tx_out_tx, ctx, io,
            );
        }
        _ => {}
    }
}

/// Walk past IPv6 extension headers (RFC 8200 §4) to find the L4 protocol
/// and its payload. Returns `None` on malformed/unknown headers or
/// `Ipv6NoNxt`.
fn skip_ipv6_ext_headers(mut next: IpProtocol, mut payload: &[u8]) -> Option<(IpProtocol, &[u8])> {
    // Cap iterations: a well-formed packet has at most a handful of ext headers.
    for _ in 0..8 {
        match next {
            IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                if payload.len() < 8 {
                    return None;
                }
                // hdr_ext_len is in 8-octet units, NOT counting the first 8 bytes.
                let hdr_len = (payload[1] as usize + 1) * 8;
                if payload.len() < hdr_len {
                    return None;
                }
                next = IpProtocol::from(payload[0]);
                payload = &payload[hdr_len..];
            }
            IpProtocol::Ipv6Frag => {
                // Fragment header is fixed 8 bytes. We only forward the first
                // fragment (offset == 0); subsequent fragments are dropped
                // since reassembly is out of scope for this proxy.
                if payload.len() < 8 {
                    return None;
                }
                let frag_offset = u16::from_be_bytes([payload[2], payload[3]]) >> 3;
                if frag_offset != 0 {
                    return None;
                }
                next = IpProtocol::from(payload[0]);
                payload = &payload[8..];
            }
            IpProtocol::Ipv6NoNxt => return None,
            _ => return Some((next, payload)),
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn dispatch_l4(
    proto: IpProtocol,
    payload: &[u8],
    src_ip: IpAddress,
    dst_ip: IpAddress,
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    tx_out_tx: &chan::Sender<Vec<u8>>,
    ctx: &RouteCtx,
    io: &mut IoCtx<'_>,
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
            // Resolve upstream destination per egress + local-service rules.
            // Blocked + non-local destination → drop the SYN; smoltcp never
            // listens, guest sees connection timeout / RST.
            let upstream = match ctx.resolve_tcp(key.dst_ip, key.dst_port) {
                Some(addr) => addr,
                None => {
                    eprintln!(
                        "[netstack] tcp drop (egress=blocked, no local-service match): {} → {}:{}",
                        key.src_port, key.dst_ip, key.dst_port,
                    );
                    return;
                }
            };
            register_tcp_flow(key, upstream, sockets, tcp_flows, io);
        }
        IpProtocol::Udp => {
            if !ctx.allows_upstream() {
                return;
            }
            let udp = match UdpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(_) => return,
            };
            let key = UdpKey {
                src_ip,
                src_port: udp.src_port(),
                dst_ip,
                dst_port: udp.dst_port(),
            };
            // If the 4-tuple is already tracked, smoltcp will deliver this
            // packet to the existing socket in the next burst poll.  The main
            // loop reads it from sock.recv() and forwards it upstream then.
            // (Forwarding it here too would double-send.)
            if udp_flows.contains_key(&key) {
                return;
            }
            register_udp_flow(key, sockets, udp_flows, ctx, io);
            let _ = tx_out_tx;
        }
        IpProtocol::Icmp => {
            if !ctx.allows_upstream() {
                return;
            }
            handle_icmpv4_echo(payload, src_ip, dst_ip, tx_out_tx);
        }
        IpProtocol::Icmpv6 => {
            if !ctx.allows_upstream() {
                return;
            }
            handle_icmpv6_echo(payload, src_ip, dst_ip, tx_out_tx);
        }
        _ => {}
    }
}

fn register_tcp_flow(
    key: TcpKey,
    upstream: SocketAddr,
    sockets: &mut SocketSet<'_>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    io: &mut IoCtx<'_>,
) {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    let listen_ep = IpListenEndpoint {
        addr: None, // any_ip=true makes this match any dst IP; None is more reliable than Some(key.dst_ip)
        port: key.dst_port,
    };
    if let Err(e) = sock.listen(listen_ep) {
        eprintln!("[netstack] tcp listen {:?}: {e}", listen_ep);
        return;
    }
    sock.set_nagle_enabled(false);
    sock.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    // Hold the SYN-ACK until the upstream connect completes.  This prevents
    // the guest from starting to send data before we know whether the
    // upstream is reachable.
    sock.pause_synack(true);
    let handle = sockets.add(sock);

    // Non-blocking connect: returns immediately, completion is signalled
    // via a WRITABLE event from the main Poll once the kernel finishes the
    // handshake (or via take_error()/peer_addr() returning failure).
    let mut upstream_sock = match MioTcpStream::connect(upstream) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[netstack] connect {} fail: {}", upstream, e);
            // Abort the listening socket so the guest sees RST instead of
            // a hang. The listener is in Listen state — abort() is the
            // smoltcp way to send a RST.
            let s = sockets.get_mut::<tcp::Socket>(handle);
            s.abort();
            sockets.remove(handle);
            return;
        }
    };
    let token = io.alloc_token();
    if let Err(e) = io
        .registry
        .register(&mut upstream_sock, token, Interest::READABLE | Interest::WRITABLE)
    {
        eprintln!("[netstack] tcp register {} fail: {}", upstream, e);
        let s = sockets.get_mut::<tcp::Socket>(handle);
        s.abort();
        sockets.remove(handle);
        return;
    }

    tcp_flows.insert(
        key,
        TcpFlow {
            handle,
            upstream: upstream_sock,
            token,
            state: TcpUpstreamState::Connecting,
            pending_to_upstream: VecDeque::new(),
            pending_to_guest: None,
            last_activity: Instant::now(),
            closed: false,
            synack_unpaused: false,
        },
    );
    eprintln!("[netstack] tcp flow opened {} → {}", key.src_port, upstream);
}

fn register_udp_flow(
    key: UdpKey,
    sockets: &mut SocketSet<'_>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    ctx: &RouteCtx,
    io: &mut IoCtx<'_>,
) {
    // smoltcp UDP socket bound to key.dst_port.  With any_ip=true this catches
    // all guest traffic to that port regardless of dst IP.  Note: two concurrent
    // flows with the same dst_port but different src will both try to bind; the
    // second bind fails and is logged — this is acceptable for the common case.
    let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]);
    let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]);
    let mut sock = udp::Socket::new(rx_buf, tx_buf);
    if let Err(e) = sock.bind(key.dst_port) {
        eprintln!("[netstack] udp bind port {}: {e}", key.dst_port);
        return;
    }
    let sock_handle = sockets.add(sock);

    // DNS proxy: guest queries to (gateway, 53) get redirected to the host's
    // real resolver so the guest's /etc/resolv.conf can safely point at the
    // gateway IP without leaking host DNS topology.
    let is_gateway = matches!(key.dst_ip, IpAddress::Ipv4(ip) if ip == HOST_IP)
        || matches!(key.dst_ip, IpAddress::Ipv6(ip) if ip == HOST_IP6);
    let dns_rewrite = if is_gateway && key.dst_port == 53 {
        ctx.host_dns
    } else {
        None
    };

    // Determine the actual upstream target address and bind the socket to the
    // matching family. When DNS proxy rewrites to a different family (e.g.
    // guest→v4 gateway but host DNS is v6), the socket must be bound to the
    // target family.
    let upstream_dst = dns_rewrite.unwrap_or_else(|| SocketAddr::new(ipaddr_to_std(key.dst_ip), key.dst_port));
    let bind_addr: SocketAddr = if upstream_dst.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut upstream = match MioUdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[netstack] upstream udp bind: {e}");
            sockets.remove(sock_handle);
            return;
        }
    };
    let token = io.alloc_token();
    if let Err(e) = io.registry.register(&mut upstream, token, Interest::READABLE) {
        eprintln!("[netstack] mio register udp: {e}");
        sockets.remove(sock_handle);
        return;
    }

    // The initial payload is NOT forwarded here — smoltcp will deliver it to
    // the newly-created socket in the next burst poll and the main loop will
    // forward it then.  Forwarding here too would double-send the packet.

    udp_flows.insert(
        key,
        UdpFlow {
            sock_handle,
            upstream,
            remote: smoltcp::wire::IpEndpoint {
                addr: key.src_ip,
                port: key.src_port,
            },
            // family_v4 tracks the guest's original request family so reply
            // frames are built in the correct format.
            family_v4: matches!(key.dst_ip, IpAddress::Ipv4(_)),
            last_activity: Instant::now(),
            dns_rewrite,
        },
    );

    eprintln!(
        "[netstack] udp flow opened {}:{} → {}{}",
        key.src_ip,
        key.src_port,
        upstream_dst,
        if dns_rewrite.is_some() { " (dns proxy)" } else { "" }
    );
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
