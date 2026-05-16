//! Win32 ICMP echo backend (IcmpSendEcho / Icmp6SendEcho2).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub(crate) fn send_echo_v4(target: Ipv4Addr, payload: &[u8], timeout: Duration) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};

    unsafe {
        let h: HANDLE = match IcmpCreateFile() {
            Ok(h) if !h.is_invalid() => h,
            _ => return false,
        };
        let mut reply_buf = vec![0u8; 64 + payload.len()];
        // IPAddr is u32 packed as octet[0]|octet[1]<<8|octet[2]<<16|octet[3]<<24
        let dst_be = u32::from_le_bytes(target.octets());
        let n = IcmpSendEcho(
            h,
            dst_be,
            payload.as_ptr() as *const _,
            payload.len() as u16,
            None,
            reply_buf.as_mut_ptr() as *mut _,
            reply_buf.len() as u32,
            timeout.as_millis() as u32,
        );
        let _ = IcmpCloseHandle(h);
        n > 0
    }
}

pub(crate) fn send_echo_v6(target: Ipv6Addr, payload: &[u8], timeout: Duration) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle};
    use windows::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

    unsafe {
        let h: HANDLE = match Icmp6CreateFile() {
            Ok(h) if !h.is_invalid() => h,
            _ => return false,
        };

        let mut src: SOCKADDR_IN6 = std::mem::zeroed();
        src.sin6_family = AF_INET6;

        let mut dst: SOCKADDR_IN6 = std::mem::zeroed();
        dst.sin6_family = AF_INET6;
        dst.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 { Byte: target.octets() },
        };

        let mut reply_buf = vec![0u8; 256 + payload.len()];

        let n = Icmp6SendEcho2(
            h,
            None,
            None,
            Some(std::ptr::null()),
            &src,
            &dst,
            payload.as_ptr() as *const _,
            payload.len() as u16,
            None,
            reply_buf.as_mut_ptr() as *mut _,
            reply_buf.len() as u32,
            timeout.as_millis() as u32,
        );
        let _ = IcmpCloseHandle(h);
        n > 0
    }
}
