//! `tokimo-tun-pump` — Linux guest-side TUN ↔ vsock bridge.
//!
//! Spawned by `init.sh` when the kernel cmdline has
//! `tokimo.net=netstack tokimo.netstack_port=<port>`. Creates (or reopens)
//! `/dev/net/tun` as a tap device named `tk0`, configures the link with the
//! gateway IP / MAC programmed by the host's `imp::netstack`, and pumps
//! Ethernet frames in both directions over an AF_VSOCK stream connection
//! to the host.
//!
//! Wire framing on the vsock: `u16-be length || ethernet frame`.
//!
//! On non-Linux targets this binary is a stub that exits non-zero so the
//! workspace still builds.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tokimo-tun-pump is Linux-only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = imp::run() {
        eprintln!("[tun-pump] fatal: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::env;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::io::FromRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    /// Topology constants — must agree with `imp::netstack` on the host.
    const TUN_NAME: &str = "tk0";
    const VSOCK_HOST_CID: u32 = 2; // VMADDR_CID_HOST
    const HOST_CONNECT_RETRY_MS: u64 = 250;
    const HOST_CONNECT_TIMEOUT_S: u64 = 30;

    pub fn run() -> Result<(), String> {
        let port: u32 = env::args()
            .nth(1)
            .ok_or("usage: tokimo-tun-pump <vsock-port>")?
            .parse()
            .map_err(|e| format!("bad port: {e}"))?;

        // 1. Create /dev/net/tun device node if it doesn't exist (initrd
        //    may not have it pre-created until tun.ko is loaded).
        ensure_tun_devnode()?;

        // 2. Open the TUN device as a TAP (Ethernet) interface.
        let tap = open_tap(TUN_NAME)?;
        eprintln!("[tun-pump] opened tap {} (fd {})", TUN_NAME, tap.as_raw_fd());

        // 3. Connect to host netstack over vsock (CID 2 = host).
        let vsock = connect_vsock_with_retry(VSOCK_HOST_CID, port)?;
        eprintln!("[tun-pump] connected vsock host:{}", port);

        // 4. Pump in both directions. Use blocking I/O on each thread.
        let shutdown = Arc::new(AtomicBool::new(false));

        let tap_fd = tap.as_raw_fd();
        let vsock_fd = vsock.as_raw_fd();
        // Duplicate fds for the two threads so each owns its own.
        let tap_a = dup_fd(tap_fd)?;
        let tap_b = dup_fd(tap_fd)?;
        let vsock_a = dup_fd(vsock_fd)?;
        let vsock_b = dup_fd(vsock_fd)?;

        let sd1 = Arc::clone(&shutdown);
        let t1 = thread::Builder::new()
            .name("tap-to-vsock".into())
            .spawn(move || {
                let mut tap = unsafe { std::fs::File::from_raw_fd(tap_a) };
                let mut vsock = unsafe { std::fs::File::from_raw_fd(vsock_a) };
                let mut buf = vec![0u8; 65536];
                while !sd1.load(Ordering::Relaxed) {
                    match tap.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if write_frame(&mut vsock, &buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                sd1.store(true, Ordering::Relaxed);
            })
            .map_err(|e| format!("spawn tap-to-vsock: {e}"))?;

        let sd2 = Arc::clone(&shutdown);
        let t2 = thread::Builder::new()
            .name("vsock-to-tap".into())
            .spawn(move || {
                let mut tap = unsafe { std::fs::File::from_raw_fd(tap_b) };
                let mut vsock = unsafe { std::fs::File::from_raw_fd(vsock_b) };
                while !sd2.load(Ordering::Relaxed) {
                    match read_frame(&mut vsock) {
                        Ok(frame) => {
                            if tap.write_all(&frame).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                sd2.store(true, Ordering::Relaxed);
            })
            .map_err(|e| format!("spawn vsock-to-tap: {e}"))?;

        let _ = t1.join();
        let _ = t2.join();
        eprintln!("[tun-pump] both directions ended, exiting");
        Ok(())
    }

    fn ensure_tun_devnode() -> Result<(), String> {
        if std::path::Path::new("/dev/net/tun").exists() {
            return Ok(());
        }
        std::fs::create_dir_all("/dev/net").map_err(|e| format!("mkdir /dev/net: {e}"))?;
        // tun major=10, minor=200.
        let dev: libc::dev_t = unsafe { libc::makedev(10, 200) };
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

    /// Open `/dev/net/tun` as a tap device, claim `name`, set IFF_NO_PI so
    /// frames are bare Ethernet (no 4-byte protocol prefix).
    fn open_tap(name: &str) -> Result<OwnedFd, String> {
        const IFF_TAP: i16 = 0x0002;
        const IFF_NO_PI: i16 = 0x1000;
        const TUNSETIFF: libc::c_ulong = 0x4004_54CA;

        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("open /dev/net/tun: {e}"))?;

        // struct ifreq { char ifr_name[16]; short ifr_flags; ... }; total
        // sizeof on Linux x86_64 = 40 bytes.
        let mut ifr = [0u8; 40];
        let nb = name.as_bytes();
        if nb.len() >= 16 {
            return Err("ifname too long".into());
        }
        ifr[..nb.len()].copy_from_slice(nb);
        let flags = (IFF_TAP | IFF_NO_PI) as i16;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());

        let r = unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) };
        if r < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(format!("TUNSETIFF: errno={errno}"));
        }
        Ok(f.into())
    }

    fn connect_vsock_with_retry(cid: u32, port: u32) -> Result<OwnedFd, String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(HOST_CONNECT_TIMEOUT_S);
        let mut last_err = String::new();
        while std::time::Instant::now() < deadline {
            match connect_vsock_once(cid, port) {
                Ok(fd) => return Ok(fd),
                Err(e) => {
                    last_err = e;
                    thread::sleep(Duration::from_millis(HOST_CONNECT_RETRY_MS));
                }
            }
        }
        Err(format!("vsock connect timeout: {last_err}"))
    }

    fn connect_vsock_once(cid: u32, port: u32) -> Result<OwnedFd, String> {
        const AF_VSOCK: i32 = 40;
        let s = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if s < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(format!("socket: errno={errno}"));
        }
        let mut addr: MaybeUninit<libc::sockaddr_vm> = MaybeUninit::zeroed();
        unsafe {
            let p = addr.as_mut_ptr();
            (*p).svm_family = AF_VSOCK as u16;
            (*p).svm_reserved1 = 0;
            (*p).svm_port = port;
            (*p).svm_cid = cid;
        }
        let r = unsafe {
            libc::connect(
                s,
                addr.as_ptr() as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if r != 0 {
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::close(s) };
            return Err(format!("connect: errno={errno}"));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(s) })
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
}
