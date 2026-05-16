//! Unix ICMP echo backend using unprivileged `SOCK_DGRAM` ICMP sockets.
//!
//! macOS supports `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` and
//! `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)` without root since 10.x.
//! The kernel overrides the ICMP identifier with the socket's local port,
//! and the recv side strips the IP header (we receive just the ICMP message
//! starting at the type byte).

use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

fn set_recv_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const _,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Internet checksum (RFC 1071) over `data`. Used for ICMPv4; ICMPv6 is
/// computed by the kernel for SOCK_DGRAM sockets.
fn rfc1071_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn send_echo_v4(target: Ipv4Addr, payload: &[u8], timeout: Duration) -> bool {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return false;
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if set_recv_timeout(owned.as_raw_fd(), timeout).is_err() {
        return false;
    }

    // Build ICMP echo request: type, code, checksum(0), id(0; kernel overrides), seq, data.
    let mut pkt = vec![0u8; 8 + payload.len()];
    pkt[0] = ICMPV4_ECHO_REQUEST;
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    pkt[4] = 0; // ident — kernel overrides
    pkt[5] = 0;
    pkt[6] = 0; // seq
    pkt[7] = 1;
    pkt[8..].copy_from_slice(payload);
    let cs = rfc1071_checksum(&pkt);
    pkt[2..4].copy_from_slice(&cs.to_be_bytes());

    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = u32::from_ne_bytes(target.octets());

    let sent = unsafe {
        libc::sendto(
            owned.as_raw_fd(),
            pkt.as_ptr() as *const _,
            pkt.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return false;
    }

    let deadline = Instant::now() + timeout;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => return false,
        };
        if set_recv_timeout(owned.as_raw_fd(), remaining).is_err() {
            return false;
        }
        let n = unsafe { libc::recv(owned.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n <= 0 {
            return false;
        }
        let n = n as usize;
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        // macOS SOCK_DGRAM ICMP returns the full IPv4 packet (header + ICMP).
        // Skip the IPv4 header — IHL is the low nibble of byte 0 in 32-bit words.
        let icmp = if !data.is_empty() && (data[0] >> 4) == 4 {
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if data.len() < ihl {
                continue;
            }
            &data[ihl..]
        } else {
            data
        };
        if icmp.len() >= 8 && icmp[0] == ICMPV4_ECHO_REPLY {
            return true;
        }
    }
}

pub(crate) fn send_echo_v6(target: Ipv6Addr, payload: &[u8], timeout: Duration) -> bool {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6) };
    if fd < 0 {
        return false;
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if set_recv_timeout(owned.as_raw_fd(), timeout).is_err() {
        return false;
    }

    // ICMPv6 echo request: type=128, code=0, checksum (kernel fills), id, seq, data.
    let mut pkt = vec![0u8; 8 + payload.len()];
    pkt[0] = ICMPV6_ECHO_REQUEST;
    pkt[1] = 0;
    // checksum left zero — kernel computes pseudo-header for SOCK_DGRAM ICMPV6.
    pkt[4] = 0;
    pkt[5] = 0;
    pkt[6] = 0;
    pkt[7] = 1;
    pkt[8..].copy_from_slice(payload);

    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = 0;
    sa.sin6_addr.s6_addr = target.octets();

    let sent = unsafe {
        libc::sendto(
            owned.as_raw_fd(),
            pkt.as_ptr() as *const _,
            pkt.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return false;
    }

    let deadline = Instant::now() + timeout;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => return false,
        };
        if set_recv_timeout(owned.as_raw_fd(), remaining).is_err() {
            return false;
        }
        let n = unsafe { libc::recv(owned.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n <= 0 {
            return false;
        }
        let n = n as usize;
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if data.len() >= 8 && data[0] == ICMPV6_ECHO_REPLY {
            return true;
        }
    }
}
