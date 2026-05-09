//! Integration test: echo round-trip via guest-agent vsock RPC.
//!
//! Spawns a real cloud-hypervisor microVM, waits for the guest-agent to come
//! up, then executes `/bin/echo hi` inside the VM and verifies that:
//!  - stdout is `"hi\n"`
//!  - exit code is `0`
//!
//! # Prerequisites
//!
//! - `/dev/kvm` accessible (user in `kvm` group)
//! - `/dev/vhost-vsock` present
//! - `bin/cloud-hypervisor/current/bin/cloud-hypervisor` available
//! - `bin/ch-vmlinux/current/bin/vmlinux` available
//! - `bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz` built (`make ch-initrd`)
//!
//! # Running
//!
//! ```sh
//! cargo test -p tokimo-package-sandbox -- --ignored echo_hi_round_trip
//! ```

use std::time::{Duration, Instant};

use tokimo_package_sandbox::SandboxBackend;
use tokimo_package_sandbox::ch::ChBackend;
use tokimo_package_sandbox::ch::vmm::{ch_initrd_path, ch_vmlinux_path};
use tokimo_package_sandbox::ch_probe::probe_ch;
use tokimo_package_sandbox::{ConfigureParams, Event, ShellOpts};

/// Returns a skip reason string if the host cannot run CH VMs.
fn skip_reason() -> Option<String> {
    let probe = probe_ch();
    if !probe.is_ready() {
        return Some(format!("host not ready for cloud-hypervisor:\n{}", probe.report()));
    }
    match ch_initrd_path() {
        Err(e) => return Some(format!("ch_initrd_path error: {e}")),
        Ok(p) if !p.exists() => {
            return Some(format!("initrd not found at '{}' — run: make ch-initrd", p.display()));
        }
        Ok(_) => {}
    }
    match ch_vmlinux_path() {
        Err(e) => return Some(format!("ch_vmlinux_path error: {e}")),
        Ok(p) if !p.exists() => {
            return Some(format!("vmlinux not found at '{}' — run: make ch-vmlinux", p.display()));
        }
        Ok(_) => {}
    }
    None
}

/// Spawn `/bin/echo hi` inside a microVM, collect stdout + exit, assert correctness.
///
/// The test is `#[ignore]` because it requires KVM hardware access, a built
/// initrd, and a cloud-hypervisor binary — not available in standard CI.
#[test]
#[ignore = "requires KVM + cloud-hypervisor binary + initrd (make ch-initrd)"]
fn echo_hi_round_trip() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP: {reason}");
        return;
    }

    // ── Construct backend ────────────────────────────────────────────────────
    let probe = probe_ch();
    let backend = ChBackend::new(probe).expect("ChBackend::new");

    // ── Configure ────────────────────────────────────────────────────────────
    backend
        .configure(ConfigureParams {
            memory_mb: 256,
            cpu_count: 1,
            ..Default::default()
        })
        .expect("configure");

    // ── Boot VM (blocks until guest-agent ping succeeds) ─────────────────────
    let t_boot_start = Instant::now();
    backend.create_vm().expect("create_vm + guest-agent ping");
    let t_boot = t_boot_start.elapsed();
    println!("VM boot + guest-agent ready: {t_boot:.2?}");

    backend.start_vm().expect("start_vm");

    // ── Subscribe before spawning so we don't miss events ───────────────────
    let rx = backend.subscribe().expect("subscribe");

    // ── Spawn /bin/echo hi ───────────────────────────────────────────────────
    let t_spawn = Instant::now();
    let shell_id = backend
        .spawn_shell(ShellOpts {
            argv: Some(vec!["/bin/echo".into(), "hi".into()]),
            ..Default::default()
        })
        .expect("spawn_shell");

    // ── Collect events until Exit ────────────────────────────────────────────
    let mut stdout_acc: Vec<u8> = Vec::new();
    let mut exit_code: Option<i32> = None;
    let deadline = Instant::now() + Duration::from_secs(10);

    while exit_code.is_none() && Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Event::Stdout { id, data }) if id == shell_id => {
                stdout_acc.extend_from_slice(&data);
            }
            Ok(Event::Stderr { id, data }) if id == shell_id => {
                eprintln!("echo stderr: {}", String::from_utf8_lossy(&data));
            }
            Ok(Event::Exit {
                id, exit_code: code, ..
            }) if id == shell_id => {
                exit_code = Some(code);
            }
            Ok(Event::Error { id, message, .. }) if id.as_ref().map(|i| i == &shell_id).unwrap_or(false) => {
                panic!("guest error: {message}");
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let elapsed = t_spawn.elapsed();

    // ── Assert ───────────────────────────────────────────────────────────────
    let stdout_str = String::from_utf8_lossy(&stdout_acc);
    assert_eq!(stdout_str.trim(), "hi", "stdout should be 'hi', got: {stdout_str:?}");
    assert_eq!(exit_code, Some(0), "exit code should be 0, got: {exit_code:?}");

    println!("echo round-trip elapsed: {elapsed:.2?}");

    // ── Shutdown ─────────────────────────────────────────────────────────────
    backend.stop_vm().expect("stop_vm");
}
