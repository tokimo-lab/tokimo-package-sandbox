//! HCN (computenetwork.dll) FFI for the SYSTEM service.
//!
//! Loads `computenetwork.dll` dynamically via `LoadLibraryW` /
//! `GetProcAddress`. Used to create a Hyper-V NAT network and a per-session
//! endpoint that the guest VM is attached to via the HCS schema's
//! `Devices.NetworkAdapters` map. Tear-down is RAII: dropping
//! `HcnEndpoint` deletes the endpoint, dropping `HcnNetwork` closes (but
//! does NOT delete) the shared NAT network.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, OnceLock};

use windows::Win32::Foundation::{FreeLibrary, HLOCAL, HMODULE, LocalFree};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{GUID, HSTRING, PCSTR};

pub type HcnHandle = *mut c_void;
type Hres = i32;

// computenetwork.dll exports — all "extern system" thiscall-free C functions.
type PfnCreateNetwork =
    unsafe extern "system" fn(GUID, *const u16, *mut HcnHandle, *mut *mut u16) -> Hres;
type PfnOpenNetwork =
    unsafe extern "system" fn(GUID, *mut HcnHandle, *mut *mut u16) -> Hres;
type PfnCloseNetwork = unsafe extern "system" fn(HcnHandle) -> Hres;
type PfnDeleteNetwork = unsafe extern "system" fn(GUID, *mut *mut u16) -> Hres;
type PfnCreateEndpoint = unsafe extern "system" fn(
    HcnHandle,
    GUID,
    *const u16,
    *mut HcnHandle,
    *mut *mut u16,
) -> Hres;
type PfnDeleteEndpoint = unsafe extern "system" fn(GUID, *mut *mut u16) -> Hres;
type PfnCloseEndpoint = unsafe extern "system" fn(HcnHandle) -> Hres;

struct HcnApi {
    module: HMODULE,
    create_network: PfnCreateNetwork,
    open_network: PfnOpenNetwork,
    close_network: PfnCloseNetwork,
    #[allow(dead_code)]
    delete_network: PfnDeleteNetwork,
    create_endpoint: PfnCreateEndpoint,
    delete_endpoint: PfnDeleteEndpoint,
    close_endpoint: PfnCloseEndpoint,
}

unsafe impl Send for HcnApi {}
unsafe impl Sync for HcnApi {}

impl Drop for HcnApi {
    fn drop(&mut self) {
        if !self.module.is_invalid() {
            unsafe {
                let _ = FreeLibrary(self.module);
            }
        }
    }
}

static HCN: OnceLock<Option<Arc<HcnApi>>> = OnceLock::new();

fn api() -> Result<Arc<HcnApi>, String> {
    HCN.get_or_init(|| HcnApi::load().ok().map(Arc::new))
        .clone()
        .ok_or_else(|| {
            "computenetwork.dll not available — Hyper-V Host Compute Network feature missing?"
                .to_string()
        })
}

impl HcnApi {
    fn load() -> Result<Self, String> {
        let dll = HSTRING::from("computenetwork.dll");
        let module = unsafe { LoadLibraryW(&dll) }
            .map_err(|e| format!("LoadLibrary computenetwork.dll: {e}"))?;

        macro_rules! resolve {
            ($name:literal, $ty:ty) => {{
                let addr = unsafe { GetProcAddress(module, PCSTR(concat!($name, "\0").as_ptr())) };
                match addr {
                    Some(a) => unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(a)
                    },
                    None => return Err(format!("missing export: {}", $name)),
                }
            }};
        }

        Ok(HcnApi {
            module,
            create_network: resolve!("HcnCreateNetwork", PfnCreateNetwork),
            open_network: resolve!("HcnOpenNetwork", PfnOpenNetwork),
            close_network: resolve!("HcnCloseNetwork", PfnCloseNetwork),
            delete_network: resolve!("HcnDeleteNetwork", PfnDeleteNetwork),
            create_endpoint: resolve!("HcnCreateEndpoint", PfnCreateEndpoint),
            delete_endpoint: resolve!("HcnDeleteEndpoint", PfnDeleteEndpoint),
            close_endpoint: resolve!("HcnCloseEndpoint", PfnCloseEndpoint),
        })
    }
}

/// Stable network GUID for the shared `tokimo-sandbox-nat` network.
/// Generated once and reused across all sessions / svc restarts.
const NETWORK_GUID: GUID = GUID::from_u128(0x9c5b7d3a_4e21_4b8f_8a0c_ef017a83d201);

/// Owned HCN network handle. The network is shared across sessions —
/// we open-or-create on first use and only close (not delete) on drop.
pub struct HcnNetwork {
    api: Arc<HcnApi>,
    handle: HcnHandle,
    id: GUID,
}

unsafe impl Send for HcnNetwork {}
unsafe impl Sync for HcnNetwork {}

impl HcnNetwork {
    /// Open or create the shared NAT network used by every sandbox VM.
    pub fn create_or_open_nat() -> Result<Self, String> {
        let api = api()?;
        let id = NETWORK_GUID;

        // Try to open first.
        let mut handle: HcnHandle = ptr::null_mut();
        let mut err_record: *mut u16 = ptr::null_mut();
        let hr = unsafe { (api.open_network)(id, &mut handle, &mut err_record) };
        free_error_record(err_record);
        if hr >= 0 && !handle.is_null() {
            return Ok(HcnNetwork {
                api,
                handle,
                id,
            });
        }

        // Otherwise create. Schema reference: HCN NetworkSchema 2.x uses
        // Ipams[].Subnets[].IpAddressPrefix with Routes[].NextHop being the
        // gateway. The older AddressPrefix/GatewayAddress shape is rejected
        // by current HCN with "UnknownField {GatewayAddress}".
        let settings = serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 16 },
            "Owner": "tokimo-sandbox",
            "Name": "tokimo-sandbox-nat",
            "Type": "NAT",
            "Ipams": [
                {
                    "Type": "Static",
                    "Subnets": [
                        {
                            "IpAddressPrefix": "192.168.127.0/24",
                            "Routes": [
                                {
                                    "NextHop": "192.168.127.1",
                                    "DestinationPrefix": "0.0.0.0/0"
                                }
                            ]
                        }
                    ]
                }
            ],
            "Flags": 0
        })
        .to_string();
        let _ = std::fs::write(r"C:\tokimo-debug\last-hcn-network.json", &settings);

        let settings_w = wide_z(&settings);
        let mut handle: HcnHandle = ptr::null_mut();
        let mut err_record: *mut u16 = ptr::null_mut();
        let hr = unsafe {
            (api.create_network)(
                id,
                settings_w.as_ptr(),
                &mut handle,
                &mut err_record,
            )
        };
        let detail = take_error_record(err_record);
        if hr < 0 {
            return Err(format!(
                "HcnCreateNetwork: 0x{:08X} — {detail}",
                hr as u32
            ));
        }
        Ok(HcnNetwork {
            api,
            handle,
            id,
        })
    }

    /// Create a new endpoint attached to this network. Each session must
    /// call this to obtain a unique GUID + DHCP-assigned IP.
    pub fn create_endpoint(&self) -> Result<HcnEndpoint, String> {
        let endpoint_id = random_guid();
        let net_id_str = format!("{:?}", self.id); // bare GUID, no braces
        let mac = random_hyperv_mac();
        // HCN endpoint with a fixed IPv4 in our NAT subnet. The Hyper-V NAT
        // gateway lives at .1; we hand .2 to this endpoint. Without a static
        // IpConfiguration HCS rejects attaching the NIC ("Construct" failure)
        // because the endpoint state is incomplete.
        let settings = serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 16 },
            "HostComputeNetwork": net_id_str,
            "MacAddress": mac,
            "IpConfigurations": [
                {
                    "IpAddress": "192.168.127.2",
                    "PrefixLength": 24
                }
            ],
            "Routes": [
                {
                    "NextHop": "192.168.127.1",
                    "DestinationPrefix": "0.0.0.0/0"
                }
            ],
            "Dns": {
                "ServerList": ["1.1.1.1", "8.8.8.8"]
            }
        })
        .to_string();
        let _ = std::fs::write(r"C:\tokimo-debug\last-hcn-endpoint.json", &settings);
        let settings_w = wide_z(&settings);

        let mut handle: HcnHandle = ptr::null_mut();
        let mut err_record: *mut u16 = ptr::null_mut();
        let hr = unsafe {
            (self.api.create_endpoint)(
                self.handle,
                endpoint_id,
                settings_w.as_ptr(),
                &mut handle,
                &mut err_record,
            )
        };
        let detail = take_error_record(err_record);
        if hr < 0 {
            return Err(format!(
                "HcnCreateEndpoint: 0x{:08X} — {detail}",
                hr as u32
            ));
        }
        Ok(HcnEndpoint {
            api: self.api.clone(),
            handle,
            id: endpoint_id,
            mac,
        })
    }
}

impl Drop for HcnNetwork {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = (self.api.close_network)(self.handle);
            }
        }
    }
}

/// Owned HCN endpoint. Drop deletes the endpoint (frees host resources).
pub struct HcnEndpoint {
    api: Arc<HcnApi>,
    handle: HcnHandle,
    id: GUID,
    mac: String,
}

unsafe impl Send for HcnEndpoint {}
unsafe impl Sync for HcnEndpoint {}

impl HcnEndpoint {
    /// Bare GUID (no braces, uppercase hex) suitable for an HCS
    /// `NetworkAdapters` key / `EndpointId` field.
    pub fn id_string(&self) -> String {
        guid_bare(&self.id)
    }

    /// MAC address in HCS dash-delimited format (`00-15-5D-XX-XX-XX`).
    pub fn mac_string(&self) -> &str {
        &self.mac
    }
}

impl Drop for HcnEndpoint {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = (self.api.close_endpoint)(self.handle);
            }
        }
        let mut err_record: *mut u16 = ptr::null_mut();
        unsafe {
            let _ = (self.api.delete_endpoint)(self.id, &mut err_record);
        }
        free_error_record(err_record);
    }
}

// --- helpers ---------------------------------------------------------------

fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn free_error_record(p: *mut u16) {
    if !p.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(p as *mut _)));
        }
    }
}

fn take_error_record(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let s = unsafe { wide_to_string(p) };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(p as *mut _)));
    }
    s
}

fn guid_bare(g: &GUID) -> String {
    let d4 = g.data4;
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g.data1, g.data2, g.data3,
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

fn random_guid() -> GUID {
    // Cheap PRNG based on time + counter — uniqueness within a host is
    // sufficient for endpoint IDs.
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&t.to_le_bytes());
    bytes[8..].copy_from_slice(&n.to_le_bytes());
    // Force version 4 / variant 1 so the GUID looks well-formed.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    GUID::from_values(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8..16].try_into().unwrap(),
    )
}

fn random_hyperv_mac() -> String {
    // Hyper-V dynamic MAC OUI: 00-15-5D-XX-XX-XX
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static CTR: AtomicU32 = AtomicU32::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mix = n.wrapping_mul(0x9E37_79B1).wrapping_add(t);
    let b3 = ((mix >> 16) & 0xFF) as u8;
    let b4 = ((mix >> 8) & 0xFF) as u8;
    let b5 = (mix & 0xFF) as u8;
    format!("00-15-5D-{:02X}-{:02X}-{:02X}", b3, b4, b5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_bare_format() {
        let g = GUID::from_u128(0x9c5b7d3a_4e21_4b8f_8a0c_ef017a83d201);
        let s = guid_bare(&g);
        assert_eq!(s.len(), 36);
        assert!(s.chars().filter(|&c| c == '-').count() == 4);
    }

    #[test]
    fn random_guid_is_unique() {
        let a = random_guid();
        let b = random_guid();
        assert_ne!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn random_mac_has_hyperv_oui() {
        let mac = random_hyperv_mac();
        assert!(mac.starts_with("00-15-5D-"));
        assert_eq!(mac.len(), 17);
    }
}
