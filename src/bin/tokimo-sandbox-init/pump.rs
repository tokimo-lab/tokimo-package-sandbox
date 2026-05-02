//! Linux bwrap netstack pump.
//!
//! When the host backend invokes init with `--net-fd=N`, init has been
//! exec'd into a fresh net namespace (bwrap `--unshare-net`). This module
//! creates `tk0` (TAP), configures the link to match the topology baked
//! into `crate::netstack` on the host, then runs two threads that pump
//! length-prefixed Ethernet frames between `tk0` and the inherited
//! socketpair fd. The host end of the same socketpair drives smoltcp.
//!
//! Topology is hard-coded to match `tokimo_package_sandbox::netstack`:
//!   - guest IP4: 192.168.127.2/24, gateway 192.168.127.1
//!   - guest IP6: fd00:7f::2/64,    gateway fd00:7f::1
//!   - guest MAC: 02:00:00:00:00:02
//!   - MTU:       1400

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

const TUN_NAME: &str = "tk0";
const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const MTU: i32 = 1400;
const IP4: [u8; 4] = [192, 168, 127, 2];
const IP4_PREFIX: u8 = 24;
const GW4: [u8; 4] = [192, 168, 127, 1];
const IP6: [u16; 8] = [0xfd00, 0x007f, 0, 0, 0, 0, 0, 0x0002];
const IP6_PREFIX: u8 = 64;
const GW6: [u16; 8] = [0xfd00, 0x007f, 0, 0, 0, 0, 0, 0x0001];

/// Bring up tk0 and pump frames between it and `net_fd` until either side
/// errors. Spawns two background threads and returns immediately.
pub fn spawn_pump(net_fd: RawFd) -> Result<Arc<AtomicBool>, String> {
    ensure_tun_devnode()?;
    let tap = open_tap(TUN_NAME)?;
    eprintln!("[init/pump] tk0 created (fd {})", tap.as_raw_fd());

    configure_link()?;
    eprintln!(
        "[init/pump] tk0 configured ({}.{}.{}.{}/{}, gw {}.{}.{}.{})",
        IP4[0], IP4[1], IP4[2], IP4[3], IP4_PREFIX, GW4[0], GW4[1], GW4[2], GW4[3]
    );

    let shutdown = Arc::new(AtomicBool::new(false));

    let tap_a = dup_fd(tap.as_raw_fd())?;
    let tap_b = dup_fd(tap.as_raw_fd())?;
    let net_a = dup_fd(net_fd)?;
    let net_b = dup_fd(net_fd)?;
    drop(tap);
    // We do NOT close net_fd — caller still holds the inherited fd; we
    // duplicated it for our own threads' independent ownership.

    let sd1 = Arc::clone(&shutdown);
    thread::Builder::new()
        .name("pump-tap-to-host".into())
        .spawn(move || {
            let mut tap = unsafe { std::fs::File::from_raw_fd(tap_a) };
            let mut net = unsafe { std::fs::File::from_raw_fd(net_a) };
            let mut buf = vec![0u8; 65536];
            while !sd1.load(Ordering::Relaxed) {
                match tap.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if write_frame(&mut net, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            sd1.store(true, Ordering::Relaxed);
            eprintln!("[init/pump] tap→host thread exit");
        })
        .map_err(|e| format!("spawn pump-tap-to-host: {e}"))?;

    let sd2 = Arc::clone(&shutdown);
    thread::Builder::new()
        .name("pump-host-to-tap".into())
        .spawn(move || {
            let mut tap = unsafe { std::fs::File::from_raw_fd(tap_b) };
            let mut net = unsafe { std::fs::File::from_raw_fd(net_b) };
            while !sd2.load(Ordering::Relaxed) {
                match read_frame(&mut net) {
                    Ok(frame) => {
                        if tap.write_all(&frame).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            sd2.store(true, Ordering::Relaxed);
            eprintln!("[init/pump] host→tap thread exit");
        })
        .map_err(|e| format!("spawn pump-host-to-tap: {e}"))?;

    Ok(shutdown)
}

fn ensure_tun_devnode() -> Result<(), String> {
    if std::path::Path::new("/dev/net/tun").exists() {
        return Ok(());
    }
    std::fs::create_dir_all("/dev/net").map_err(|e| format!("mkdir /dev/net: {e}"))?;
    let dev: libc::dev_t = libc::makedev(10, 200);
    let path = std::ffi::CString::new("/dev/net/tun").unwrap();
    let r = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o666, dev) };
    if r != 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EEXIST {
            return Ok(());
        }
        return Err(format!("mknod /dev/net/tun: errno={errno}"));
    }
    Ok(())
}

fn open_tap(name: &str) -> Result<OwnedFd, String> {
    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x4004_54CA;

    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| format!("open /dev/net/tun: {e}"))?;
    let mut ifr = [0u8; 40];
    let nb = name.as_bytes();
    if nb.len() >= 16 {
        return Err("ifname too long".into());
    }
    ifr[..nb.len()].copy_from_slice(nb);
    let flags: i16 = IFF_TAP | IFF_NO_PI;
    ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
    let r = unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) };
    if r < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("TUNSETIFF: errno={errno}"));
    }
    Ok(f.into())
}

fn dup_fd(fd: i32) -> Result<i32, String> {
    let r = unsafe { libc::dup(fd) };
    if r < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("dup: errno={errno}"));
    }
    Ok(r)
}

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr)?;
    let len = u16::from_be_bytes(hdr) as usize;
    if len == 0 || len > 65535 {
        return Err(std::io::Error::other(format!("bad frame len {len}")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame<W: Write>(w: &mut W, frame: &[u8]) -> std::io::Result<()> {
    if frame.len() > 65535 {
        return Err(std::io::Error::other("frame too large"));
    }
    let hdr = (frame.len() as u16).to_be_bytes();
    w.write_all(&hdr)?;
    w.write_all(frame)?;
    Ok(())
}

// ─── Link configuration ──────────────────────────────────────────────────────

fn configure_link() -> Result<(), String> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(format!("socket(AF_INET): {}", std::io::Error::last_os_error()));
    }
    let _guard = scopeguard_close(sock);

    set_mac(sock, TUN_NAME, GUEST_MAC)?;
    set_mtu(sock, TUN_NAME, MTU)?;
    set_ipv4(sock, TUN_NAME, IP4, IP4_PREFIX)?;
    set_iff_up(sock, TUN_NAME)?;
    add_ipv4_default_route(sock, GW4)?;

    // IPv6: assign address, default route. Best-effort — host may have
    // disabled v6 (cgroup or sysctl), in which case we log and continue.
    if let Err(e) = enable_ipv6_on_link(TUN_NAME) {
        eprintln!("[init/pump] WARN enable v6: {e}");
    }
    if let Err(e) = add_ipv6_addr(TUN_NAME, IP6, IP6_PREFIX) {
        eprintln!("[init/pump] WARN v6 addr: {e}");
    }
    if let Err(e) = add_ipv6_default_route(TUN_NAME, GW6) {
        eprintln!("[init/pump] WARN v6 route: {e}");
    }
    Ok(())
}

struct CloseOnDrop(RawFd);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}
fn scopeguard_close(fd: RawFd) -> CloseOnDrop {
    CloseOnDrop(fd)
}

fn ifr_with_name(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let nb = name.as_bytes();
    for (i, &b) in nb.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn set_mac(sock: RawFd, name: &str, mac: [u8; 6]) -> Result<(), String> {
    let mut ifr = ifr_with_name(name);
    unsafe {
        ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER;
        for (i, &b) in mac.iter().enumerate() {
            ifr.ifr_ifru.ifru_hwaddr.sa_data[i] = b as libc::c_char;
        }
    }
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFHWADDR as _, &ifr) };
    if r != 0 {
        return Err(format!("SIOCSIFHWADDR: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn set_mtu(sock: RawFd, name: &str, mtu: i32) -> Result<(), String> {
    let mut ifr = ifr_with_name(name);
    ifr.ifr_ifru.ifru_mtu = mtu;
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr) };
    if r != 0 {
        return Err(format!("SIOCSIFMTU: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn set_ipv4(sock: RawFd, name: &str, addr: [u8; 4], prefix: u8) -> Result<(), String> {
    // Address.
    let mut ifr = ifr_with_name(name);
    unsafe {
        let sa: &mut libc::sockaddr_in = &mut *(&mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut _);
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr.s_addr = u32::from_ne_bytes(addr);
    }
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr) };
    if r != 0 {
        return Err(format!("SIOCSIFADDR: {}", std::io::Error::last_os_error()));
    }

    // Netmask.
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    let mut ifr = ifr_with_name(name);
    unsafe {
        let sa: &mut libc::sockaddr_in = &mut *(&mut ifr.ifr_ifru.ifru_netmask as *mut _ as *mut _);
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr.s_addr = mask.to_be();
    }
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr) };
    if r != 0 {
        return Err(format!("SIOCSIFNETMASK: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn set_iff_up(sock: RawFd, name: &str) -> Result<(), String> {
    let mut ifr = ifr_with_name(name);
    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    let r = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
    if r != 0 {
        return Err(format!("SIOCSIFFLAGS: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn add_ipv4_default_route(sock: RawFd, gw: [u8; 4]) -> Result<(), String> {
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    unsafe {
        let dst: &mut libc::sockaddr_in = &mut *(&mut rt.rt_dst as *mut _ as *mut _);
        dst.sin_family = libc::AF_INET as libc::sa_family_t;
        dst.sin_addr.s_addr = 0;

        let gwa: &mut libc::sockaddr_in = &mut *(&mut rt.rt_gateway as *mut _ as *mut _);
        gwa.sin_family = libc::AF_INET as libc::sa_family_t;
        gwa.sin_addr.s_addr = u32::from_ne_bytes(gw);

        let mask: &mut libc::sockaddr_in = &mut *(&mut rt.rt_genmask as *mut _ as *mut _);
        mask.sin_family = libc::AF_INET as libc::sa_family_t;
        mask.sin_addr.s_addr = 0;

        rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    }
    let r = unsafe { libc::ioctl(sock, libc::SIOCADDRT as _, &rt) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        // EEXIST means a default route already exists — fine.
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("SIOCADDRT default: {err}"));
        }
    }
    Ok(())
}

fn enable_ipv6_on_link(name: &str) -> Result<(), String> {
    for (key, val) in [
        ("disable_ipv6", "0"),
        ("accept_dad", "0"),
        ("dad_transmits", "0"),
        ("accept_ra", "0"),
    ] {
        let path = format!("/proc/sys/net/ipv6/conf/{name}/{key}");
        std::fs::write(&path, val).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

fn add_ipv6_addr(name: &str, addr: [u16; 8], prefix: u8) -> Result<(), String> {
    // Use AF_INET6 + SIOCSIFADDR via in6_ifreq.
    #[repr(C)]
    struct In6Ifreq {
        ifr6_addr: [u8; 16],
        ifr6_prefixlen: u32,
        ifr6_ifindex: i32,
    }
    const SIOCSIFADDR6: libc::c_ulong = 0x8916; // SIOCSIFADDR for v6 share same number; kernel disambiguates by AF.

    let sock6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock6 < 0 {
        return Err(format!("socket AF_INET6: {}", std::io::Error::last_os_error()));
    }
    let _g = scopeguard_close(sock6);

    let ifindex = if_nametoindex(name)?;
    let mut bytes = [0u8; 16];
    for (i, &w) in addr.iter().enumerate() {
        let be = w.to_be_bytes();
        bytes[i * 2] = be[0];
        bytes[i * 2 + 1] = be[1];
    }
    let req = In6Ifreq {
        ifr6_addr: bytes,
        ifr6_prefixlen: prefix as u32,
        ifr6_ifindex: ifindex as i32,
    };
    let r = unsafe { libc::ioctl(sock6, SIOCSIFADDR6 as _, &req) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("SIOCSIFADDR (v6): {err}"));
        }
    }
    Ok(())
}

fn add_ipv6_default_route(name: &str, gw: [u16; 8]) -> Result<(), String> {
    #[repr(C)]
    struct In6RtMsg {
        rtmsg_dst: [u8; 16],
        rtmsg_src: [u8; 16],
        rtmsg_gateway: [u8; 16],
        rtmsg_type: u32,
        rtmsg_dst_len: u16,
        rtmsg_src_len: u16,
        rtmsg_metric: u32,
        rtmsg_info: libc::c_ulong,
        rtmsg_flags: u32,
        rtmsg_ifindex: i32,
    }
    const SIOCADDRT6: libc::c_ulong = 0x890b; // same as SIOCADDRT; AF disambiguates.

    let sock6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock6 < 0 {
        return Err(format!("socket AF_INET6 (route): {}", std::io::Error::last_os_error()));
    }
    let _g = scopeguard_close(sock6);

    let ifindex = if_nametoindex(name)? as i32;
    let mut gwb = [0u8; 16];
    for (i, &w) in gw.iter().enumerate() {
        let be = w.to_be_bytes();
        gwb[i * 2] = be[0];
        gwb[i * 2 + 1] = be[1];
    }
    let req = In6RtMsg {
        rtmsg_dst: [0; 16],
        rtmsg_src: [0; 16],
        rtmsg_gateway: gwb,
        rtmsg_type: 1, // RTN_UNICAST
        rtmsg_dst_len: 0,
        rtmsg_src_len: 0,
        rtmsg_metric: 1,
        rtmsg_info: 0,
        rtmsg_flags: (libc::RTF_UP | libc::RTF_GATEWAY) as u32,
        rtmsg_ifindex: ifindex,
    };
    let r = unsafe { libc::ioctl(sock6, SIOCADDRT6 as _, &req) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("SIOCADDRT (v6): {err}"));
        }
    }
    Ok(())
}

fn if_nametoindex(name: &str) -> Result<u32, String> {
    let cs = std::ffi::CString::new(name).map_err(|e| format!("CString: {e}"))?;
    let idx = unsafe { libc::if_nametoindex(cs.as_ptr()) };
    if idx == 0 {
        return Err(format!("if_nametoindex({name}): {}", std::io::Error::last_os_error()));
    }
    Ok(idx)
}
