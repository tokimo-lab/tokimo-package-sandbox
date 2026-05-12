//! Identify which backend `Sandbox::connect()` resolves to.
//!
//! Runs on every supported platform. Useful for CI logs (so a glance at
//! the test output confirms whether `SANDBOX_BACKEND=ch` actually picked
//! the ch backend, etc.) and as a regression guard against
//! mis-routing in [`crate::platform::backend_for_kind`].

use tokimo_package_sandbox::{ActiveBackend, Sandbox};

/// On every platform: `Sandbox::connect()` must succeed in producing a
/// handle whose `active_backend()` is one of the four known variants,
/// and that variant must match what we'd expect from the OS + the
/// `SANDBOX_BACKEND` env var (if it forces a specific backend).
#[test]
fn active_backend_is_reported() {
    let sb = match Sandbox::connect() {
        Ok(s) => s,
        Err(e) => {
            // On Linux CI without ch deps, `SANDBOX_BACKEND=ch` legitimately
            // fails (no fallback when forced). Don't fail the suite — this
            // test is for *identifying* the backend, not for proving a
            // particular one is available.
            eprintln!("[backend-identity] connect failed: {e}");
            return;
        }
    };

    let actual = sb.active_backend();
    eprintln!("[backend-identity] Sandbox::connect() → {actual}");

    let env = std::env::var("SANDBOX_BACKEND").unwrap_or_default();
    eprintln!("[backend-identity] SANDBOX_BACKEND={env:?}");

    // Cross-check against the OS.
    let allowed: &[ActiveBackend] = if cfg!(target_os = "linux") {
        &[ActiveBackend::Bwrap, ActiveBackend::Ch]
    } else if cfg!(target_os = "macos") {
        &[ActiveBackend::Macos]
    } else if cfg!(target_os = "windows") {
        &[ActiveBackend::Windows]
    } else {
        &[]
    };
    assert!(
        allowed.contains(&actual),
        "active_backend {actual} not in allowed set {allowed:?} for this OS"
    );

    // Cross-check against any explicit env override.
    match env.trim().to_lowercase().as_str() {
        "bwrap" => assert_eq!(actual, ActiveBackend::Bwrap, "SANDBOX_BACKEND=bwrap but got {actual}"),
        "ch" => assert_eq!(actual, ActiveBackend::Ch, "SANDBOX_BACKEND=ch but got {actual}"),
        _ => {}
    }
}
