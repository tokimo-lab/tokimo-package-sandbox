//! L4↔L7 bridge: a tiny shared cache that lets the L7 HTTP(S) proxy attach
//! `pid`/`comm` to its events (by peeking at the L4 observer's recent
//! connects) and that lets the L4 observer suppress the noise event it would
//! otherwise emit for connects that merely land on the proxy's own socket.
//!
//! Resolution strategy (lookup side, called from the proxy's `accept` path):
//!
//! 1. Proxy gets `client.peer_addr()` = `127.0.0.1:<ephem>`.
//! 2. Read `/proc/net/tcp` + `/proc/net/tcp6`, find the row whose local
//!    address matches `<ephem>` and whose remote address matches
//!    `127.0.0.1:<proxy_port>`. That row gives us the owning UID + inode.
//! 3. Walk `/proc/<pid>/fd/*` looking for a socket fd whose link resolves to
//!    `socket:[<inode>]`. First pid wins.
//! 4. Read `/proc/<pid>/comm`.
//!
//! Best-effort: on lookup failure the event is still emitted, just without
//! pid/comm. The lookup is cheap (one open of two small files + one directory
//! walk capped at recent pids) and happens off the tracer thread.
//!
//! The L4 side uses `proxy_port()` directly to short-circuit: if the remote
//! of a `connect()` is `127.0.0.1:<proxy_port>`, the L4 backend skips the
//! emit — the L7 proxy will produce a merged event shortly after.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

#[derive(Default)]
pub(crate) struct L4L7Bridge {
    /// Port the L7 proxy is listening on, or 0 when unset.
    proxy_port: AtomicU16,
}

impl L4L7Bridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_proxy_port(&self, port: u16) {
        self.proxy_port.store(port, Ordering::SeqCst);
    }

    pub fn proxy_port(&self) -> u16 {
        self.proxy_port.load(Ordering::SeqCst)
    }

    /// Returns true if `addr` is a connect the proxy will handle itself
    /// (i.e. 127.0.0.1 / ::1 on the proxy's own listen port). L4 backends
    /// should skip such events to avoid duplicates.
    pub fn is_proxy_target(&self, addr: &SocketAddr) -> bool {
        let pp = self.proxy_port();
        if pp == 0 {
            return false;
        }
        addr.port() == pp && addr.ip().is_loopback()
    }

    /// Look up the (pid, comm) of whoever connected to our proxy from
    /// `client_peer`. `client_peer` is the proxy socket's `peer_addr()`
    /// (i.e. what `accept()` told us).
    pub fn resolve_pid(&self, client_peer: SocketAddr) -> Option<(u32, String)> {
        let proxy_port = self.proxy_port();
        if proxy_port == 0 {
            return None;
        }

        let inode = match client_peer.ip() {
            IpAddr::V4(v4) => find_socket_inode_v4(v4, client_peer.port(), proxy_port)?,
            IpAddr::V6(v6) => find_socket_inode_v6(v6, client_peer.port(), proxy_port)?,
        };
        let pid = find_pid_by_inode(inode)?;
        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim_end_matches('\n').to_string())
            .unwrap_or_default();
        Some((pid, comm))
    }
}

/// Scan `/proc/net/tcp` for a row whose local port is `local_port` and
/// remote is `127.0.0.1:<proxy_port>`. Returns the socket inode.
fn find_socket_inode_v4(local_ip: Ipv4Addr, local_port: u16, proxy_port: u16) -> Option<u64> {
    let text = fs::read_to_string("/proc/net/tcp").ok()?;
    let want_local = ipv4_to_proc_hex(local_ip);
    parse_proc_net_for_inode(&text, |l_addr, l_port, r_addr, r_port| {
        l_port == local_port
            && r_port == proxy_port
            && l_addr.eq_ignore_ascii_case(&want_local)
            && is_loopback_hex4(r_addr)
    })
}

fn ipv4_to_proc_hex(ip: Ipv4Addr) -> String {
    // /proc/net/tcp encodes IPv4 as 8 hex chars of the address's bytes in
    // **little-endian** order, e.g. 127.0.0.1 -> "0100007F".
    let o = ip.octets();
    format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0])
}

fn find_socket_inode_v6(local_ip: Ipv6Addr, local_port: u16, proxy_port: u16) -> Option<u64> {
    // Dual-stack sockets show up in /proc/net/tcp6 even if the peer is v4.
    let text = fs::read_to_string("/proc/net/tcp6").ok()?;
    let _ = local_ip;
    parse_proc_net_for_inode(&text, |_l_addr, l_port, _r_addr, r_port| {
        l_port == local_port && r_port == proxy_port
    })
}

fn is_loopback_hex4(hex: &str) -> bool {
    // "0100007F" = 127.0.0.1 (little-endian octets). Accept any 127/8.
    hex.len() == 8 && hex.get(6..8).map(|s| s.eq_ignore_ascii_case("7F")).unwrap_or(false)
}

fn parse_proc_net_for_inode<F>(text: &str, mut matches: F) -> Option<u64>
where
    F: FnMut(&str, u16, &str, u16) -> bool,
{
    for line in text.lines().skip(1) {
        let mut it = line.split_whitespace();
        let _sl = it.next()?;
        let local = it.next()?;
        let remote = it.next()?;
        let _st = it.next()?;
        let _tx_rx = it.next()?;
        let _tr_when = it.next()?;
        let _retrnsmt = it.next()?;
        let _uid = it.next()?;
        let _timeout = it.next()?;
        let inode = it.next()?;
        let (l_addr, l_port) = split_addr_port(local)?;
        let (r_addr, r_port) = split_addr_port(remote)?;
        if matches(l_addr, l_port, r_addr, r_port) {
            return inode.parse().ok();
        }
    }
    None
}

fn split_addr_port(s: &str) -> Option<(&str, u16)> {
    let (addr, port) = s.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((addr, port))
}

/// Scan `/proc/*/fd/*` for a symlink matching `socket:[<inode>]`.
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let needle = format!("socket:[{}]", inode);
    let proc = fs::read_dir("/proc").ok()?;
    for entry in proc.flatten() {
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        let Ok(pid) = name_s.parse::<u32>() else {
            continue;
        };
        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path())
                && link.to_string_lossy() == needle
            {
                return Some(pid);
            }
        }
    }
    None
}
