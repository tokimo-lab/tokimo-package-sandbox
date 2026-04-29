//! tokimo-sandbox-svc — Windows SYSTEM service for HCS VM management.
//!
//! Dispatching and SCM plumbing use the `windows-service` crate. All other
//! Win32 calls go through the `windows` crate. Hand-rolled `extern "system"`
//! blocks are only used for `vmcompute.dll` HCS exports which aren't yet
//! covered by an official binding.
//!
//! ## Modes
//!
//! ```text
//!   tokimo-sandbox-svc                 # run as Windows service (called by SCM)
//!   tokimo-sandbox-svc --install       # legacy: create service via SCM (admin)
//!   tokimo-sandbox-svc --uninstall     # legacy: remove service (admin)
//!   tokimo-sandbox-svc --console       # foreground pipe server (debugging)
//! ```
//!
//! The recommended deploy mechanism is the MSIX in `packaging/windows/`,
//! which registers the service via `desktop6:Service` in `AppxManifest.xml`
//! and avoids any UAC prompt.
//!
//! ## Security
//!
//! - Pipe ACL grants `GENERIC_ALL` to `LocalSystem`, and read/write only to
//!   the `Interactive Users` group (SDDL well-known SID `IU`). `Builtin
//!   Users` is **not** granted any access — that was the old vulnerability.
//! - On every connection we resolve the calling process's image path via
//!   `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW` and log
//!   it. If `TOKIMO_VERIFY_CALLER=1` is set in the service's environment
//!   (or `HKLM\SOFTWARE\Tokimo\SandboxSvc\VerifyCaller=1`), the caller's
//!   Authenticode signature is checked via `WinVerifyTrust`; unsigned or
//!   untrusted callers are rejected.
//! - Every path received over the wire (kernel, initrd, VHDX, workspace)
//!   is canonicalised and rejected if it contains a symlink, junction, or
//!   has multiple hard links.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("tokimo-sandbox-svc is Windows-only");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
mod imp;

#[cfg(target_os = "windows")]
fn main() {
    imp::run();
}
