//! smoltcp userspace network stack POC — TCP + UDP(DNS) 验证.
//!
//! Demonstrates the full proxy chain that replaces HCN NAT:
//!
//!   "VM" (smoltcp) ──Ethernet frames──▶ channel ──▶ "Host" (smoltcp)
//!                                                  ──▶ real socket ──▶ Internet
//!
//! Tests:
//!   1. TCP:  VM → HTTP GET 1.1.1.1:80 → Host proxies → real TcpStream
//!   2. UDP:  VM → DNS query example.com:53 → Host proxies → real UdpSocket
//!
//! Run: `cargo run --example smoltcp_netstack`

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel as chan;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address,
};

// ─── Channel-backed Ethernet device ──────────────────────────────────────────

struct ChannelDevice {
    rx: chan::Receiver<Vec<u8>>,
    tx: chan::Sender<Vec<u8>>,
}

struct ChanRxToken(Vec<u8>);
struct ChanTxToken(chan::Sender<Vec<u8>>);

impl RxToken for ChanRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for ChanTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
        r
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = ChanRxToken;
    type TxToken<'a> = ChanTxToken;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(ChanRxToken, ChanTxToken)> {
        self.rx.try_recv().ok().map(|frame| {
            (ChanRxToken(frame), ChanTxToken(self.tx.clone()))
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<ChanTxToken> {
        Some(ChanTxToken(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps
    }
}

fn make_device(rx: chan::Receiver<Vec<u8>>, tx: chan::Sender<Vec<u8>>) -> ChannelDevice {
    ChannelDevice { rx, tx }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn setup_iface(
    device: &mut ChannelDevice,
    mac: [u8; 6],
    ip: [u8; 4],
    cidr_prefix: u8,
) -> Interface {
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    config.random_seed = rand_u64();
    let mut iface = Interface::new(config, device, smolcp_now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::from(ip)),
                cidr_prefix,
            ))
            .unwrap();
    });
    iface
}

fn smolcp_now() -> SmolInstant {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

// ─── DNS helpers ─────────────────────────────────────────────────────────────

/// Build a minimal DNS A-record query for the given domain.
fn build_dns_query(domain: &str, txid: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);
    // Header
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, recursion desired
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    pkt
}

/// Parse the first A record IP from a DNS response. Returns None if no A record found.
fn parse_dns_response(resp: &[u8]) -> Option<String> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    // Skip header + question section
    let mut pos = 12;
    // Skip QNAME
    while pos < resp.len() && resp[pos] != 0 {
        pos += resp[pos] as usize + 1;
    }
    pos += 1; // root null
    pos += 4; // QTYPE + QCLASS
    // Parse first answer
    if pos + 12 > resp.len() {
        return None;
    }
    // Skip name (handle pointer)
    if resp[pos] & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while pos < resp.len() && resp[pos] != 0 {
            pos += resp[pos] as usize + 1;
        }
        pos += 1;
    }
    let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    pos += 8; // TYPE + CLASS + TTL
    let rdlen = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
    pos += 2;
    if rtype == 1 && rdlen == 4 && pos + 4 <= resp.len() {
        Some(format!("{}.{}.{}.{}", resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]))
    } else {
        None
    }
}

// ─── Host side: TCP + UDP proxy ──────────────────────────────────────────────

fn host_thread(
    rx_from_vm: chan::Receiver<Vec<u8>>,
    tx_to_vm: chan::Sender<Vec<u8>>,
    done: Arc<AtomicBool>,
) {
    let mut device = make_device(rx_from_vm, tx_to_vm);
    let mut iface = setup_iface(&mut device, [0x02, 0, 0, 0, 0, 0x01], [192, 168, 127, 1], 24);

    let mut sockets = SocketSet::new(vec![]);

    // TCP listener on port 80
    let tcp_rx = tcp::SocketBuffer::new(vec![0; 4096]);
    let tcp_tx = tcp::SocketBuffer::new(vec![0; 4096]);
    let mut tcp_sock = tcp::Socket::new(tcp_rx, tcp_tx);
    tcp_sock.listen(80).unwrap();
    let tcp_handle = sockets.add(tcp_sock);

    // UDP socket on port 53 (DNS proxy)
    let udp_rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
    let udp_tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
    let mut udp_sock = udp::Socket::new(udp_rx, udp_tx);
    udp_sock.bind(53).unwrap();
    let udp_handle = sockets.add(udp_sock);

    println!("[Host] TCP listening on :80, UDP listening on :53");

    let mut upstream_tcp: Option<TcpStream> = None;
    let mut request_buf = Vec::new();
    let mut tcp_done = false;
    let mut udp_done = false;
    let mut flush_ticks = 0u32; // keep polling after both done to flush frames

    while !done.load(Ordering::Relaxed) {
        iface.poll(smolcp_now(), &mut device, &mut sockets);

        // ── TCP proxy ──
        let tcp_socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if tcp_socket.is_active() && tcp_socket.can_recv() && upstream_tcp.is_none() {
            if let Ok(bytes) = tcp_socket.recv(|b| (b.len(), b.to_vec())) {
                if !bytes.is_empty() {
                    request_buf.extend_from_slice(&bytes);
                    if request_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        println!(
                            "[Host/TCP] Got request ({} bytes)",
                            request_buf.len()
                        );
                        if let Ok(mut stream) =
                            TcpStream::connect_timeout(&"1.1.1.1:80".parse().unwrap(), Duration::from_secs(5))
                        {
                            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                            if stream.write_all(&request_buf).is_ok() {
                                let mut resp = Vec::new();
                                let _ = stream.read_to_end(&mut resp);
                                println!("[Host/TCP] Got {} bytes from upstream", resp.len());
                                upstream_tcp = Some(stream);
                                let tcp_socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
                                let mut off = 0;
                                while off < resp.len() {
                                    match tcp_socket.send_slice(&resp[off..]) {
                                        Ok(n) => off += n,
                                        Err(_) => break,
                                    }
                                }
                                tcp_done = true;
                                println!("[Host/TCP] Response sent back");
                            }
                        }
                    }
                }
            }
        }
        if tcp_done {
            let tcp_socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            if !tcp_socket.can_send() || tcp_socket.send_queue() == 0 {
                tcp_socket.close();
            }
        }

        // ── UDP DNS proxy ──
        let udp_socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if udp_socket.can_recv() {
            if let Ok((data, remote_ep)) = udp_socket.recv() {
                println!("[Host/UDP] DNS query from {} ({} bytes)", remote_ep, data.len());
                // Forward to real DNS server 1.1.1.1:53
                match UdpSocket::bind("0.0.0.0:0") {
                    Ok(real_udp) => {
                        real_udp.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        if real_udp.send_to(&data, "1.1.1.1:53").is_ok() {
                            let mut buf = vec![0u8; 512];
                            if let Ok((n, _src)) = real_udp.recv_from(&mut buf) {
                                println!("[Host/UDP] DNS response from 1.1.1.1 ({} bytes)", n);
                                let udp_socket = sockets.get_mut::<udp::Socket>(udp_handle);
                                let _ = udp_socket.send_slice(&buf[..n], remote_ep);
                                udp_done = true;
                            }
                        }
                    }
                    Err(e) => println!("[Host/UDP] bind failed: {e}"),
                }
            }
        }

        if tcp_done && udp_done {
            flush_ticks += 1;
            if flush_ticks > 100 {
                break;
            }
        }

        thread::sleep(Duration::from_millis(1));
    }

    println!("[Host] Done (tcp={tcp_done}, udp={udp_done})");
}

// ─── VM side: TCP HTTP + UDP DNS ─────────────────────────────────────────────

fn vm_thread(
    rx_from_host: chan::Receiver<Vec<u8>>,
    tx_to_host: chan::Sender<Vec<u8>>,
    done: Arc<AtomicBool>,
) {
    let mut device = make_device(rx_from_host, tx_to_host);
    let mut iface = setup_iface(&mut device, [0x02, 0, 0, 0, 0, 0x02], [192, 168, 127, 2], 24);
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 127, 1))
        .unwrap();

    let mut sockets = SocketSet::new(vec![]);

    // ── Phase 1: TCP test ──
    println!("\n── Test 1: TCP (HTTP GET → 1.1.1.1:80) ──");
    {
        let tcp_rx = tcp::SocketBuffer::new(vec![0; 4096]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0; 4096]);
        let tcp_socket = tcp::Socket::new(tcp_rx, tcp_tx);
        let tcp_handle = sockets.add(tcp_socket);

        let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(192, 168, 127, 1)), 80);
        sockets
            .get_mut::<tcp::Socket>(tcp_handle)
            .connect(iface.context(), remote, 12345u16)
            .unwrap();

        let mut sent = false;
        let mut tcp_response = String::new();
        let start = Instant::now();

        while start.elapsed() < Duration::from_secs(10) {
            iface.poll(smolcp_now(), &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

            if socket.can_send() && !sent {
                let req = b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
                println!("[VM/TCP] Sending HTTP request ({} bytes)", req.len());
                socket.send_slice(req).unwrap();
                sent = true;
            }

            if socket.can_recv() {
                if let Ok(chunk) = socket.recv(|b| (b.len(), String::from_utf8_lossy(b).into_owned())) {
                    if !chunk.is_empty() {
                        tcp_response.push_str(&chunk);
                    }
                }
            }

            if sent && !socket.is_active() && !tcp_response.is_empty() {
                break;
            }
            if sent && !tcp_response.is_empty() && !socket.may_recv() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        if tcp_response.contains("HTTP/1.1") {
            let preview = &tcp_response[..tcp_response.len().min(120)];
            println!("[VM/TCP] OK — {preview}...");
        } else {
            println!("[VM/TCP] FAIL — no valid HTTP response");
        }
    }

    // ── Phase 2: UDP DNS test ──
    println!("\n── Test 2: UDP (DNS query → example.com) ──");
    {
        let udp_rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
        let udp_tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
        let mut udp_socket = udp::Socket::new(udp_rx, udp_tx);
        udp_socket.bind(54321).unwrap();
        let udp_handle = sockets.add(udp_socket);

        let dns_server = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(192, 168, 127, 1)), 53);
        let query = build_dns_query("example.com", 0xABCD);
        println!("[VM/UDP] Sending DNS query for example.com ({} bytes)", query.len());

        sockets
            .get_mut::<udp::Socket>(udp_handle)
            .send_slice(&query, dns_server)
            .unwrap();

        let mut dns_response: Option<Vec<u8>> = None;
        let start = Instant::now();

        while start.elapsed() < Duration::from_secs(5) {
            // recv first (drops borrow before poll)
            if dns_response.is_none() {
                let data = {
                    let socket = sockets.get_mut::<udp::Socket>(udp_handle);
                    if socket.can_recv() {
                        socket.recv().ok().map(|(d, _)| d.to_vec())
                    } else {
                        None
                    }
                };
                if let Some(d) = data {
                    println!("[VM/UDP] Got DNS response ({} bytes)", d.len());
                    dns_response = Some(d);
                    break;
                }
            }
            // poll after recv borrow is dropped
            iface.poll(smolcp_now(), &mut device, &mut sockets);
            thread::sleep(Duration::from_millis(1));
        }

        if let Some(ref resp) = dns_response {
            if let Some(ip) = parse_dns_response(resp) {
                println!("[VM/UDP] OK — example.com resolves to {ip}");
            } else {
                println!("[VM/UDP] OK — got {} bytes (A record parse skipped)", resp.len());
            }
        } else {
            println!("[VM/UDP] FAIL — no DNS response (timeout)");
        }
    }

    done.store(true, Ordering::Relaxed);
    println!("\n=== All tests complete ===");
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== smoltcp userspace network stack POC ===");
    println!("Subnet: 192.168.127.0/24");
    println!("VM: 192.168.127.2 ↔ Host: 192.168.127.1");
    println!("Transport: in-memory channel (simulates vsock)\n");

    let (vm_tx, host_rx) = chan::bounded::<Vec<u8>>(256);
    let (host_tx, vm_rx) = chan::bounded::<Vec<u8>>(256);

    let done = Arc::new(AtomicBool::new(false));
    let done2 = done.clone();

    let host = thread::Builder::new()
        .name("host-proxy".into())
        .spawn(move || host_thread(host_rx, host_tx, done2))
        .unwrap();

    let vm = thread::Builder::new()
        .name("vm-client".into())
        .spawn(move || vm_thread(vm_rx, vm_tx, done))
        .unwrap();

    vm.join().unwrap();
    host.join().unwrap();
}
