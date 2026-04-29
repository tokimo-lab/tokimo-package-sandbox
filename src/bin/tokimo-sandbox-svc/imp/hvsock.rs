//! AF_HYPERV socket helpers for talking to a Hyper-V guest over vsock.
//!
//! `SOCKADDR_HV` and `AF_HYPERV` are not part of the `windows` crate's
//! generated bindings (Hyper-V sockets aren't in any of its families), so
//! we hand-roll the constants and address structure but call all syscalls
//! through `windows = "0.62"`'s WinSock bindings.

#![cfg(target_os = "windows")]

use std::io::{self, Read, Write};
use std::time::Duration;

use windows::Win32::Networking::WinSock::{
    INVALID_SOCKET, SEND_RECV_FLAGS, SOCK_STREAM, SOCKET, WSADATA, WSAGetLastError, WSAStartup,
    accept, bind, closesocket, connect, listen, recv, send, socket,
};
use windows::core::GUID;

const AF_HYPERV: u16 = 34;
const HV_PROTOCOL_RAW: i32 = 1;

/// HV_GUID_WILDCARD — used by host listeners to accept connections from any
/// guest VmId.
pub const HV_GUID_WILDCARD: GUID = GUID::from_u128(0x00000000_0000_0000_0000_000000000000);
/// HV_GUID_CHILDREN — host listener accepting only from children (guests
/// hosted by this partition). Per Microsoft docs this is the correct wildcard
/// for parent-partition listeners; HV_GUID_WILDCARD is broader but may not be
/// honored for cross-partition bind from a Windows host listening for a Linux
/// guest connector.
#[allow(dead_code)]
pub const HV_GUID_CHILDREN: GUID =
    GUID::from_u128(0x90db8b89_0d35_4f79_8ce9_49ea0ac8b7cd);

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrHv {
    family: u16,
    reserved: u16,
    vm_id: GUID,
    service_id: GUID,
}

fn ensure_wsa_started() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        let _ = unsafe { WSAStartup(0x0202, &mut data) };
    });
}

/// Bind an AF_HYPERV listener for `service_id`, accepting connections from
/// any guest VmId (HV_GUID_WILDCARD). Returns the listening socket which
/// must be passed to [`accept_guest`] to retrieve the connected client.
pub fn listen_for_guest(service_id: GUID) -> io::Result<HvSock> {
    ensure_wsa_started();
    let s = match unsafe { socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW) } {
        Ok(s) if s != INVALID_SOCKET => s,
        Ok(_) => {
            let err = unsafe { WSAGetLastError() }.0;
            return Err(io::Error::other(format!("AF_HYPERV socket: WSA={err}")));
        }
        Err(e) => return Err(io::Error::other(format!("AF_HYPERV socket: {e:?}"))),
    };
    let addr = SockaddrHv {
        family: AF_HYPERV,
        reserved: 0,
        vm_id: HV_GUID_WILDCARD,
        service_id,
    };
    let r = unsafe {
        bind(
            s,
            &addr as *const _ as *const _,
            std::mem::size_of::<SockaddrHv>() as i32,
        )
    };
    if r != 0 {
        let err = unsafe { WSAGetLastError() }.0;
        unsafe { let _ = closesocket(s); }
        return Err(io::Error::other(format!("AF_HYPERV bind: WSA={err}")));
    }
    let r = unsafe { listen(s, 4) };
    if r != 0 {
        let err = unsafe { WSAGetLastError() }.0;
        unsafe { let _ = closesocket(s); }
        return Err(io::Error::other(format!("AF_HYPERV listen: WSA={err}")));
    }
    Ok(HvSock { s })
}

/// Block on `accept()` until a guest connects (or `timeout` elapses).
pub fn accept_guest(listener: &HvSock, timeout: Duration) -> io::Result<HvSock> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut rfds: windows::Win32::Networking::WinSock::FD_SET = unsafe { std::mem::zeroed() };
        rfds.fd_count = 1;
        rfds.fd_array[0] = listener.s;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::other("AF_HYPERV accept timed out"));
        }
        let tv = windows::Win32::Networking::WinSock::TIMEVAL {
            tv_sec: remaining.as_secs().min(60) as i32,
            tv_usec: 0,
        };
        let nready = unsafe {
            windows::Win32::Networking::WinSock::select(0, Some(&mut rfds), None, None, Some(&tv))
        };
        if nready < 0 {
            let err = unsafe { WSAGetLastError() }.0;
            return Err(io::Error::other(format!("AF_HYPERV select: WSA={err}")));
        }
        if nready == 0 {
            continue;
        }
        let mut peer: SockaddrHv = unsafe { std::mem::zeroed() };
        let mut len: i32 = std::mem::size_of::<SockaddrHv>() as i32;
        let c = unsafe {
            accept(
                listener.s,
                Some(&mut peer as *mut _ as *mut _),
                Some(&mut len),
            )
        };
        match c {
            Ok(s) if s != INVALID_SOCKET => return Ok(HvSock { s }),
            _ => {
                let err = unsafe { WSAGetLastError() }.0;
                return Err(io::Error::other(format!("AF_HYPERV accept: WSA={err}")));
            }
        }
    }
}

/// (Legacy) Connect to a Hyper-V guest's HvSocket service. Retries on
/// connection-refused (HCS may not have wired the service yet) up to the
/// given timeout. Cowork's architecture uses host-listen instead — see
/// [`listen_for_guest`].
#[allow(dead_code)]
pub fn connect_to_guest(vm_id: GUID, service_id: GUID, timeout: Duration) -> io::Result<HvSock> {
    ensure_wsa_started();

    let deadline = std::time::Instant::now() + timeout;

    loop {
        let s = match unsafe { socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW) } {
            Ok(s) if s != INVALID_SOCKET => s,
            Ok(_) => {
                let err = unsafe { WSAGetLastError() }.0;
                return Err(io::Error::other(format!("AF_HYPERV socket: WSA={err}")));
            }
            Err(e) => {
                return Err(io::Error::other(format!("AF_HYPERV socket: {e:?}")));
            }
        };

        let addr = SockaddrHv {
            family: AF_HYPERV,
            reserved: 0,
            vm_id,
            service_id,
        };

        let r = unsafe {
            connect(
                s,
                &addr as *const _ as *const _,
                std::mem::size_of::<SockaddrHv>() as i32,
            )
        };
        if r == 0 {
            return Ok(HvSock { s });
        }
        let err = unsafe { WSAGetLastError() }.0;
        unsafe {
            let _ = closesocket(s);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "AF_HYPERV connect failed: WSA={err}"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Owned AF_HYPERV socket. Read/Write impls call WSA recv/send.
pub struct HvSock {
    s: SOCKET,
}

impl HvSock {
    pub fn try_clone(&self) -> io::Result<HvSock> {
        // Use WSADuplicateSocket-like approach via DuplicateHandle on the
        // SOCKET handle. Easier: call WSADuplicateSocket then WSASocket on
        // the protocol info. For simplicity, we instead share the same
        // SOCKET via a manually-managed Arc; since recv and send are
        // independent, both threads can safely call them concurrently on
        // the same SOCKET.
        //
        // To keep the API similar to `File::try_clone` we duplicate the
        // underlying handle via DuplicateHandle.
        use windows::Win32::Foundation::{DuplicateHandle, HANDLE};
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut dup = HANDLE::default();
        let proc = unsafe { GetCurrentProcess() };
        unsafe {
            DuplicateHandle(
                proc,
                HANDLE(self.s.0 as *mut _),
                proc,
                &mut dup,
                0,
                false,
                windows::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|e| io::Error::other(format!("DuplicateHandle SOCKET: {e:?}")))?;
        Ok(HvSock {
            s: SOCKET(dup.0 as usize),
        })
    }
}

impl Read for HvSock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { recv(self.s, buf, SEND_RECV_FLAGS(0)) };
        if n == -1 {
            let err = unsafe { WSAGetLastError() }.0;
            return Err(io::Error::other(format!("WSA recv: {err}")));
        }
        Ok(n as usize)
    }
}

impl Write for HvSock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { send(self.s, buf, SEND_RECV_FLAGS(0)) };
        if n == -1 {
            let err = unsafe { WSAGetLastError() }.0;
            return Err(io::Error::other(format!("WSA send: {err}")));
        }
        Ok(n as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for HvSock {
    fn drop(&mut self) {
        unsafe {
            let _ = closesocket(self.s);
        }
    }
}

unsafe impl Send for HvSock {}
unsafe impl Sync for HvSock {}
