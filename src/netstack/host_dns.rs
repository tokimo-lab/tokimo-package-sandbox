//! Host DNS resolver discovery.
//!
//! The guest's `/etc/resolv.conf` points at the gateway IP (`192.168.127.1`)
//! so the userspace netstack can transparently proxy DNS without leaking the
//! host's DNS topology into the sandbox. To actually resolve names, netstack
//! needs to know what upstream resolver to forward those packets to. This
//! module discovers that on each supported platform.
//!
//! Discovery is best-effort and runs once at netstack start. If it fails
//! (e.g. resolv.conf unreadable, no nameservers configured), DNS proxying is
//! disabled and guest queries to the gateway will simply time out — no worse
//! than not having a network.

use std::net::{IpAddr, SocketAddr};

/// Detect the first usable host DNS resolver. Returns `None` if no resolver
/// could be discovered or the discovered address is itself a sandbox gateway
/// (which would loopback infinitely).
pub fn detect() -> Option<SocketAddr> {
    let addr = detect_platform()?;
    if is_sandbox_gateway(addr.ip()) {
        return None;
    }
    Some(addr)
}

#[cfg(unix)]
fn detect_platform() -> Option<SocketAddr> {
    parse_resolv_conf("/etc/resolv.conf")
}

#[cfg(windows)]
fn detect_platform() -> Option<SocketAddr> {
    windows_get_network_params()
}

fn parse_resolv_conf(path: &str) -> Option<SocketAddr> {
    let body = std::fs::read_to_string(path).ok()?;
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut it = line.split_whitespace();
        if it.next() != Some("nameserver") {
            continue;
        }
        let raw = it.next()?;
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

fn is_sandbox_gateway(ip: IpAddr) -> bool {
    use crate::net_constants;
    match ip {
        IpAddr::V4(v4) => v4.octets() == net_constants::HOST_IP4_OCTETS,
        IpAddr::V6(v6) => v6.segments() == net_constants::HOST_IP6_SEGMENTS,
    }
}

#[cfg(windows)]
fn windows_get_network_params() -> Option<SocketAddr> {
    use std::ffi::CStr;
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::NetworkManagement::IpHelper::{FIXED_INFO_W2KSP1, GetNetworkParams, IP_ADDR_STRING};

    unsafe {
        let mut size: u32 = 0;
        let rc = GetNetworkParams(None, &mut size);
        if rc.0 != ERROR_BUFFER_OVERFLOW.0 && size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let info = buf.as_mut_ptr() as *mut FIXED_INFO_W2KSP1;
        let rc = GetNetworkParams(Some(info), &mut size);
        if rc.0 != 0 {
            return None;
        }
        let mut node: *const IP_ADDR_STRING = &(*info).DnsServerList;
        while !node.is_null() {
            let s = (*node).IpAddress.String.as_ptr() as *const i8;
            let cstr = CStr::from_ptr(s);
            if let Ok(text) = cstr.to_str()
                && let Ok(ip) = text.parse::<IpAddr>()
                && !ip.is_unspecified()
            {
                return Some(SocketAddr::new(ip, 53));
            }
            node = (*node).Next;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_nameserver() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# comment").unwrap();
        writeln!(tmp, "nameserver 8.8.8.8").unwrap();
        writeln!(tmp, "nameserver 1.1.1.1").unwrap();
        let got = parse_resolv_conf(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(got, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_gateway_ip() {
        assert!(is_sandbox_gateway(IpAddr::V4("192.168.127.1".parse().unwrap())));
        assert!(!is_sandbox_gateway(IpAddr::V4("8.8.8.8".parse().unwrap())));
    }
}
