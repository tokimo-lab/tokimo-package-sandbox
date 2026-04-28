//! Thin FFI + safe wrapper over the Windows Host Compute Service (HCS) API.
//!
//! HCS is the low-level VM/container management API that WSL2 and Docker
//! use under the hood. It's part of the "Virtual Machine Platform" optional
//! feature (available on Windows 10 1903+ Home/Pro/Enterprise).
//!
//! All HCS calls go through dynamically-loaded function pointers, since
//! ComputeCore.dll may not have a standard import library. LoadLibrary +
//! GetProcAddress gives us reliable linking on all Windows editions.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::core::HRESULT;

// ---------------------------------------------------------------------------
// Raw types
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
type HCS_SYSTEM = *mut c_void;
#[allow(non_camel_case_types)]
type HCS_OPERATION = *mut c_void;

type PfnCreateOperation = unsafe extern "system" fn(*mut c_void, *mut c_void) -> HCS_OPERATION;
type PfnCloseOperation = unsafe extern "system" fn(HCS_OPERATION) -> HRESULT;
type PfnCreateComputeSystem =
    unsafe extern "system" fn(*const u16, *const u16, HCS_OPERATION, *mut c_void, *mut HCS_SYSTEM) -> HRESULT;
type PfnStartComputeSystem = unsafe extern "system" fn(HCS_SYSTEM, HCS_OPERATION, *const u16) -> HRESULT;
type PfnTerminateComputeSystem = unsafe extern "system" fn(HCS_SYSTEM, HCS_OPERATION, *const u16) -> HRESULT;
type PfnCloseComputeSystem = unsafe extern "system" fn(HCS_SYSTEM) -> HRESULT;
type PfnWaitForOperationResult = unsafe extern "system" fn(HCS_OPERATION, u32, *mut HRESULT) -> HRESULT;
type PfnGetProperties = unsafe extern "system" fn(HCS_SYSTEM, *const u16, *mut *mut u16) -> HRESULT;

// kernel32 helpers
extern "system" {
    fn LoadLibraryW(lpFileName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn FreeLibrary(hModule: *mut c_void) -> i32;
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

// ---------------------------------------------------------------------------
// Dynamic function table
// ---------------------------------------------------------------------------

struct HcsFns {
    _module: *mut c_void,
    create_operation: PfnCreateOperation,
    close_operation: PfnCloseOperation,
    create_compute_system: PfnCreateComputeSystem,
    start_compute_system: PfnStartComputeSystem,
    terminate_compute_system: PfnTerminateComputeSystem,
    close_compute_system: PfnCloseComputeSystem,
    wait_for_operation_result: PfnWaitForOperationResult,
    get_properties: PfnGetProperties,
}

unsafe impl Send for HcsFns {}
unsafe impl Sync for HcsFns {}

impl Drop for HcsFns {
    fn drop(&mut self) {
        if !self._module.is_null() {
            unsafe { FreeLibrary(self._module) };
        }
    }
}

static HCS: OnceLock<Option<HcsFns>> = OnceLock::new();

fn load_hcs_fns() -> Option<&'static HcsFns> {
    HCS.get_or_init(|| {
        let dll: Vec<u16> = "ComputeCore.dll\0".encode_utf16().collect();
        let hmod = unsafe { LoadLibraryW(dll.as_ptr()) };
        if hmod.is_null() {
            return None;
        }

        macro_rules! load_fn {
            ($name:expr, $type:ty) => {{
                let addr = unsafe { GetProcAddress(hmod, concat!($name, "\0").as_ptr()) };
                if addr.is_null() {
                    unsafe { FreeLibrary(hmod) };
                    return None;
                }
                unsafe { std::mem::transmute::<*mut c_void, $type>(addr) }
            }};
        }

        let fns = HcsFns {
            _module: hmod,
            create_operation: load_fn!("HcsCreateOperation", PfnCreateOperation),
            close_operation: load_fn!("HcsCloseOperation", PfnCloseOperation),
            create_compute_system: load_fn!("HcsCreateComputeSystem", PfnCreateComputeSystem),
            start_compute_system: load_fn!("HcsStartComputeSystem", PfnStartComputeSystem),
            terminate_compute_system: load_fn!("HcsTerminateComputeSystem", PfnTerminateComputeSystem),
            close_compute_system: load_fn!("HcsCloseComputeSystem", PfnCloseComputeSystem),
            wait_for_operation_result: load_fn!("HcsWaitForOperationResult", PfnWaitForOperationResult),
            get_properties: load_fn!("HcsGetComputeSystemProperties", PfnGetProperties),
        };

        Some(fns)
    })
    .as_ref()
}

/// Check if the HCS API is available on this system.
pub fn is_available() -> bool {
    let fns = match load_hcs_fns() {
        Some(f) => f,
        None => return false,
    };
    // Quick smoke test: create + close an operation.
    let handle = unsafe { (fns.create_operation)(ptr::null_mut(), ptr::null_mut()) };
    if handle.is_null() {
        return false;
    }
    unsafe { (fns.close_operation)(handle) };
    true
}

// ---------------------------------------------------------------------------
// Safe RAII wrappers
// ---------------------------------------------------------------------------

pub struct HcsOperation {
    handle: HCS_OPERATION,
}

impl HcsOperation {
    pub fn new() -> Result<Self, HcsError> {
        let fns = load_hcs_fns().ok_or_else(|| HcsError::Other("HCS not available".into()))?;
        let handle = unsafe { (fns.create_operation)(ptr::null_mut(), ptr::null_mut()) };
        if handle.is_null() {
            return Err(HcsError::last_os_error("HcsCreateOperation"));
        }
        Ok(Self { handle })
    }

    pub fn as_raw(&self) -> HCS_OPERATION {
        self.handle
    }

    pub fn wait(&self, timeout_ms: u32) -> Result<(), HcsError> {
        let fns = load_hcs_fns().ok_or_else(|| HcsError::Other("HCS not available".into()))?;
        let mut op_result: HRESULT = 0;
        let hr = unsafe { (fns.wait_for_operation_result)(self.handle, timeout_ms, &mut op_result) };
        if hr < 0 {
            return Err(HcsError::from_hresult("HcsWaitForOperationResult", hr));
        }
        if op_result < 0 {
            return Err(HcsError::from_hresult("HcsOperation", op_result));
        }
        Ok(())
    }
}

impl Drop for HcsOperation {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Some(fns) = load_hcs_fns() {
                unsafe { (fns.close_operation)(self.handle) };
            }
        }
    }
}

pub struct HcsSystem {
    handle: HCS_SYSTEM,
}

impl HcsSystem {
    pub fn create(id: &str, config_json: &str) -> Result<Self, HcsError> {
        let fns = load_hcs_fns().ok_or_else(|| HcsError::Other("HCS not available".into()))?;
        let id_wide: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
        let config_wide: Vec<u16> = config_json.encode_utf16().chain(std::iter::once(0)).collect();

        let op = HcsOperation::new()?;
        let mut handle: HCS_SYSTEM = ptr::null_mut();

        let hr = unsafe {
            (fns.create_compute_system)(
                id_wide.as_ptr(),
                config_wide.as_ptr(),
                op.as_raw(),
                ptr::null_mut(),
                &mut handle,
            )
        };
        if hr < 0 {
            return Err(HcsError::from_hresult("HcsCreateComputeSystem", hr));
        }
        op.wait(30_000)?;

        Ok(Self { handle })
    }

    pub fn start(&self) -> Result<(), HcsError> {
        let fns = load_hcs_fns().ok_or_else(|| HcsError::Other("HCS not available".into()))?;
        let op = HcsOperation::new()?;
        let hr = unsafe { (fns.start_compute_system)(self.handle, op.as_raw(), ptr::null()) };
        if hr < 0 {
            return Err(HcsError::from_hresult("HcsStartComputeSystem", hr));
        }
        op.wait(30_000)?;
        Ok(())
    }

    pub fn terminate(&self) -> Result<(), HcsError> {
        let fns = load_hcs_fns().ok_or_else(|| HcsError::Other("HCS not available".into()))?;
        let op = HcsOperation::new()?;
        let hr = unsafe { (fns.terminate_compute_system)(self.handle, op.as_raw(), ptr::null()) };
        if hr < 0 {
            return Err(HcsError::from_hresult("HcsTerminateComputeSystem", hr));
        }
        op.wait(10_000)?;
        Ok(())
    }

    pub fn get_properties(&self, query: &str) -> Result<String, HcsError> {
        let fns = load_hcs_fns().ok_or_else(|| HcsError::Other("HCS not available".into()))?;
        let query_wide: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();
        let mut result_ptr: *mut u16 = ptr::null_mut();

        let hr = unsafe { (fns.get_properties)(self.handle, query_wide.as_ptr(), &mut result_ptr) };
        if hr < 0 {
            return Err(HcsError::from_hresult("HcsGetComputeSystemProperties", hr));
        }
        if result_ptr.is_null() {
            return Err(HcsError::Other("null properties result".into()));
        }

        let result = unsafe { read_wide_string(result_ptr) };
        unsafe { LocalFree(result_ptr as *mut c_void) };
        Ok(result)
    }
}

impl Drop for HcsSystem {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Some(fns) = load_hcs_fns() {
                unsafe { (fns.close_compute_system)(self.handle) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum HcsError {
    Hcs(String),
    Other(String),
}

impl HcsError {
    fn from_hresult(function: &'static str, hr: HRESULT) -> Self {
        Self::Hcs(format!("{function} failed: HRESULT 0x{hr:08X}"))
    }

    fn last_os_error(function: &'static str) -> Self {
        let code = unsafe { GetLastError() };
        Self::Hcs(format!("{function} failed: OS error {code}"))
    }
}

impl std::fmt::Display for HcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hcs(s) | Self::Other(s) => s.fmt(f),
        }
    }
}

impl std::error::Error for HcsError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn read_wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------
// VM configuration schema generation (HCS v2)
// ---------------------------------------------------------------------------

pub fn build_vm_config(
    id: &str,
    kernel_path: &Path,
    initrd_path: &Path,
    rootfs_path: &Path,
    cmd_b64: &str,
    memory_mb: u64,
    cpu_count: usize,
) -> String {
    let kernel = kernel_path.to_string_lossy().replace('\\', "\\\\");
    let initrd = initrd_path.to_string_lossy().replace('\\', "\\\\");
    let share_path = rootfs_path.to_string_lossy().replace('\\', "\\\\");
    let args = format!("console=ttyS0 quiet loglevel=3 run={cmd_b64}");

    let config = serde_json::json!({
        "SchemaVersion": { "Major": 2, "Minor": 0 },
        "Owner": "tokimo-sandbox",
        "VirtualMachine": {
            "ComputeTopology": {
                "Memory": {
                    "Backing": "Virtual",
                    "SizeInMB": memory_mb
                },
                "Processor": {
                    "Count": cpu_count,
                    "Maximum": cpu_count,
                    "Weight": 100
                }
            },
            "Chipset": {
                "LinuxKernel": {
                    "KernelPath": kernel,
                    "InitrdPath": initrd,
                    "Arguments": args
                }
            },
            "Devices": {
                "Plan9": {
                    "Shares": [{
                        "Name": "work",
                        "Path": share_path,
                        "Port": 564,
                        "Flags": 0
                    }]
                },
                "ComPorts": {
                    "0": {
                        "Path": format!("\\\\.\\pipe\\tokimo-{id}"),
                        "Enabled": true
                    }
                }
            },
            "StopOnGuestCrash": true
        }
    });

    config.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_vm_config_schema() {
        let json = build_vm_config(
            "test-id",
            Path::new("C:\\Users\\test\\.tokimo\\kernel\\vmlinuz"),
            Path::new("C:\\Users\\test\\.tokimo\\initrd.img"),
            Path::new("C:\\Users\\test\\.tokimo\\rootfs"),
            "dGVzdA==",
            512,
            2,
        );

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["SchemaVersion"]["Major"], 2);
        assert_eq!(parsed["SchemaVersion"]["Minor"], 0);

        let chipset = &parsed["VirtualMachine"]["Chipset"]["LinuxKernel"];
        assert!(chipset["KernelPath"].as_str().unwrap().contains("vmlinuz"));
        assert!(chipset["InitrdPath"].as_str().unwrap().contains("initrd.img"));
        assert!(chipset["Arguments"].as_str().unwrap().contains("run=dGVzdA=="));

        let shares = &parsed["VirtualMachine"]["Devices"]["Plan9"]["Shares"][0];
        assert_eq!(shares["Name"], "work");
        assert_eq!(shares["Port"], 564);
        assert_eq!(shares["Flags"], 0);
    }

    #[test]
    fn test_is_available_smoke() {
        let available = is_available();
        // On a machine with VMP enabled, this should be true.
        // Print for CI/debug visibility.
        println!("HCS is_available() = {available}");
    }
}
