//! HCS (vmcompute.dll) FFI for the SYSTEM service.
//!
//! `vmcompute.dll` exports aren't yet covered by an official `windows`
//! crate binding, so we still go through `LoadLibraryW` + `GetProcAddress`.
//! We at least use the `windows` crate for those two calls so we're not
//! hand-declaring extern blocks.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, OnceLock};

use windows::Win32::Foundation::{FreeLibrary, HLOCAL, HMODULE, LocalFree};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{HSTRING, PCSTR};

pub type CsHandle = *mut c_void;
type Op = *mut c_void;
type Hres = i32;

type PfnCreateOp = unsafe extern "system" fn(*mut c_void, *mut c_void) -> Op;
type PfnCloseOp = unsafe extern "system" fn(Op);
type PfnCreateCs = unsafe extern "system" fn(*const u16, *const u16, Op, *mut c_void, *mut CsHandle) -> Hres;
type PfnStartCs = unsafe extern "system" fn(CsHandle, Op, *const u16) -> Hres;
type PfnTerminateCs = unsafe extern "system" fn(CsHandle, Op, *const u16) -> Hres;
type PfnCloseCs = unsafe extern "system" fn(CsHandle);
type PfnWaitOp = unsafe extern "system" fn(Op, u32, *mut *mut u16) -> Hres;
type PfnGetProps = unsafe extern "system" fn(CsHandle, Op, *const u16) -> Hres;

pub struct HcsApi {
    module: HMODULE,
    create_op: PfnCreateOp,
    close_op: PfnCloseOp,
    create_cs: PfnCreateCs,
    start_cs: PfnStartCs,
    terminate_cs: PfnTerminateCs,
    close_cs: PfnCloseCs,
    wait_op: PfnWaitOp,
    get_props: PfnGetProps,
}

unsafe impl Send for HcsApi {}
unsafe impl Sync for HcsApi {}

impl Drop for HcsApi {
    fn drop(&mut self) {
        if !self.module.is_invalid() {
            unsafe {
                let _ = FreeLibrary(self.module);
            }
        }
    }
}

static HCS: OnceLock<Option<Arc<HcsApi>>> = OnceLock::new();

#[derive(Debug, PartialEq)]
pub enum HcsState {
    Running,
    Stopped,
    Error,
}

impl HcsApi {
    pub fn init() -> Result<Arc<Self>, String> {
        HCS.get_or_init(|| Self::load().ok().map(Arc::new))
            .clone()
            .ok_or_else(|| "vmcompute.dll not available — is the Hyper-V Host Compute Service installed?".to_string())
    }

    fn load() -> Result<Self, String> {
        let dll = HSTRING::from("ComputeCore.dll");
        let module = unsafe { LoadLibraryW(&dll) }.map_err(|e| format!("LoadLibrary ComputeCore.dll: {e}"))?;

        macro_rules! resolve {
            ($name:literal, $ty:ty) => {{
                let addr = unsafe { GetProcAddress(module, PCSTR(concat!($name, "\0").as_ptr())) };
                match addr {
                    Some(a) => unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(a) },
                    None => return Err(format!("missing export: {}", $name)),
                }
            }};
        }

        Ok(HcsApi {
            module,
            create_op: resolve!("HcsCreateOperation", PfnCreateOp),
            close_op: resolve!("HcsCloseOperation", PfnCloseOp),
            create_cs: resolve!("HcsCreateComputeSystem", PfnCreateCs),
            start_cs: resolve!("HcsStartComputeSystem", PfnStartCs),
            terminate_cs: resolve!("HcsTerminateComputeSystem", PfnTerminateCs),
            close_cs: resolve!("HcsCloseComputeSystem", PfnCloseCs),
            wait_op: resolve!("HcsWaitForOperationResult", PfnWaitOp),
            get_props: resolve!("HcsGetComputeSystemProperties", PfnGetProps),
        })
    }

    pub fn create_compute_system(&self, id: &str, config_json: &str) -> Result<CsHandle, String> {
        let id_w = wide_z(id);
        let cfg_w = wide_z(config_json);
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        if op.is_null() {
            return Err("HcsCreateOperation returned null".into());
        }
        let mut handle: CsHandle = ptr::null_mut();
        let hr = unsafe { (self.create_cs)(id_w.as_ptr(), cfg_w.as_ptr(), op, ptr::null_mut(), &mut handle) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return Err(format!("HcsCreateComputeSystem: 0x{:08X}", hr as u32));
        }
        self.wait_and_close(op, 30_000)
            .map_err(|e| format!("HcsCreateComputeSystem wait: {e}"))?;
        Ok(handle)
    }

    pub fn start_compute_system(&self, handle: CsHandle) -> Result<(), String> {
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        let hr = unsafe { (self.start_cs)(handle, op, ptr::null()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return Err(format!("HcsStartComputeSystem: 0x{:08X}", hr as u32));
        }
        self.wait_and_close(op, 30_000)
            .map_err(|e| format!("HcsStartComputeSystem wait: {e}"))
    }

    pub fn terminate_compute_system(&self, handle: CsHandle) -> Result<(), String> {
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        let hr = unsafe { (self.terminate_cs)(handle, op, ptr::null()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return Err(format!("HcsTerminateComputeSystem: 0x{:08X}", hr as u32));
        }
        self.wait_and_close(op, 10_000)
            .map_err(|e| format!("Terminate wait: {e}"))
    }

    pub fn close_compute_system(&self, handle: CsHandle) {
        if !handle.is_null() {
            unsafe { (self.close_cs)(handle) };
        }
    }

    fn wait_and_close(&self, op: Op, timeout_ms: u32) -> Result<(), String> {
        let mut result_ptr: *mut u16 = ptr::null_mut();
        let hr = unsafe { (self.wait_op)(op, timeout_ms, &mut result_ptr) };

        // On failure HCS may still return a result JSON with error details.
        let detail = if !result_ptr.is_null() {
            let json = unsafe { wide_to_string(result_ptr) };
            unsafe {
                let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
            }
            json
        } else {
            String::new()
        };

        unsafe { (self.close_op)(op) };

        if hr < 0 {
            if !detail.is_empty() {
                return Err(format!("HcsWaitForOperationResult: 0x{:08X} — {}", hr as u32, detail));
            }
            return Err(format!("HcsWaitForOperationResult: 0x{:08X}", hr as u32));
        }

        let ok = if detail.is_empty() { true } else { check_result(&detail) };
        if ok {
            Ok(())
        } else {
            Err("operation did not succeed".into())
        }
    }

    /// Query the VM's exit code via `HcsGetComputeSystemProperties`.
    /// Returns `None` if the property is unavailable.
    pub fn get_exit_code(&self, handle: CsHandle) -> Option<i32> {
        let q = wide_z(r#"{"PropertyTypes":[]}"#);
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        if op.is_null() {
            return None;
        }
        let hr = unsafe { (self.get_props)(handle, op, q.as_ptr()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return None;
        }
        let mut result_ptr: *mut u16 = ptr::null_mut();
        let hr2 = unsafe { (self.wait_op)(op, 5_000, &mut result_ptr) };
        unsafe { (self.close_op)(op) };
        if hr2 < 0 || result_ptr.is_null() {
            if !result_ptr.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
                }
            }
            return None;
        }
        let json = unsafe { wide_to_string(result_ptr) };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
            v["ExitCode"].as_i64().map(|n| n as i32)
        } else {
            None
        }
    }

    /// Query the runtime ID GUID assigned by HCS to this compute system.
    /// Returns the bare GUID string (no braces) on success.
    pub fn get_runtime_id(&self, handle: CsHandle) -> Option<String> {
        let q = wide_z(r#"{"PropertyTypes":[]}"#);
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        if op.is_null() {
            return None;
        }
        let hr = unsafe { (self.get_props)(handle, op, q.as_ptr()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return None;
        }
        let mut result_ptr: *mut u16 = ptr::null_mut();
        let hr2 = unsafe { (self.wait_op)(op, 5_000, &mut result_ptr) };
        unsafe { (self.close_op)(op) };
        if hr2 < 0 || result_ptr.is_null() {
            if !result_ptr.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
                }
            }
            return None;
        }
        let json = unsafe { wide_to_string(result_ptr) };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
        }
        let _ = std::fs::write(r"C:\tokimo-debug\last-hcs-props.json", &json);
        let v: serde_json::Value = serde_json::from_str(&json).ok()?;
        // RuntimeId may live at top level or under VirtualMachine depending
        // on schema. Try several locations.
        for path in [
            v.get("RuntimeId"),
            v.get("VirtualMachine").and_then(|m| m.get("RuntimeId")),
            v.get("RuntimeID"),
        ] {
            if let Some(s) = path.and_then(|x| x.as_str()) {
                let g = s.trim_matches(|c| c == '{' || c == '}');
                if !g.is_empty() {
                    return Some(g.to_string());
                }
            }
        }
        None
    }

    pub fn poll_state(&self, handle: CsHandle) -> HcsState {
        // Query default properties (includes State).
        let q = wide_z(r#"{"PropertyTypes":[]}"#);
        let op = unsafe { (self.create_op)(ptr::null_mut(), ptr::null_mut()) };
        if op.is_null() {
            return HcsState::Error;
        }
        let hr = unsafe { (self.get_props)(handle, op, q.as_ptr()) };
        if hr < 0 {
            unsafe { (self.close_op)(op) };
            return HcsState::Error;
        }
        let mut result_ptr: *mut u16 = ptr::null_mut();
        let hr2 = unsafe { (self.wait_op)(op, 5_000, &mut result_ptr) };
        unsafe { (self.close_op)(op) };
        if hr2 < 0 || result_ptr.is_null() {
            if !result_ptr.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
                }
            }
            return HcsState::Error;
        }
        let json = unsafe { wide_to_string(result_ptr) };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(result_ptr as *mut _)));
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
            // HCS returns different JSON shapes depending on VM lifecycle:
            //   Running: {"State":"Running", ...}
            //   Stopped: {"State":"Stopped", ...}  OR  {"Stopped":true,"ExitType":"GracefulExit"}
            match v.get("State").and_then(|s| s.as_str()) {
                Some("Running") => return HcsState::Running,
                Some("Stopped") => return HcsState::Stopped,
                _ => {}
            }
            if v.get("Stopped").and_then(|s| s.as_bool()).unwrap_or(false) {
                return HcsState::Stopped;
            }
            HcsState::Error
        } else {
            HcsState::Error
        }
    }
}

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

fn check_result(json: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
        if v.get("Success").and_then(|s| s.as_bool()).unwrap_or(false) {
            return true;
        }
        if let Some(code) = v.get("Result").and_then(|r| r.as_i64()) {
            return code >= 0;
        }
        if v.get("Result").and_then(|r| r.as_str()).is_some() {
            return true;
        }
        v.get("Error").is_none()
    } else {
        false
    }
}
