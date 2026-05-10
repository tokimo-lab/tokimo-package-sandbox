//! Integration test: PTY-over-vsock with Cloud Hypervisor microVM.
//!
//! Spawns a real cloud-hypervisor microVM, waits for the guest-agent to come
//! up, opens a PTY session running `/bin/sh`, writes commands, reads output,
//! and verifies exit code.
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
//! cargo test -p tokimo-package-sandbox --test ch_pty -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::ch::rpc::{GuestRpc, PtyFrame};
use tokimo_package_sandbox::ch::vmm::{ChVm, ChVmConfig, ch_initrd_path, ch_vmlinux_path, next_cid};
use tokimo_package_sandbox::ch_probe::probe_ch;

/// Returns a skip reason string if the host cannot run CH VMs.
fn skip_reason() -> Option<String> {
    // Check if /dev/kvm can actually be opened with read/write access.
    if let Err(e) = OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        return Some(format!(
            "/dev/kvm cannot be opened with read/write access: {} — \
             ensure current user is in the 'kvm' group and has proper permissions",
            e
        ));
    }

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

/// Test PTY: open shell in VM, write echo command, read output, verify.
///
/// The test is `#[ignore]` because it requires KVM hardware access, a built
/// initrd, and a cloud-hypervisor binary — not available in standard CI.
#[test]
#[ignore = "requires KVM + cloud-hypervisor binary + initrd (make ch-initrd)"]
fn ch_pty_echo_hi() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP: {reason}");
        return;
    }

    // ── Construct VM config ──────────────────────────────────────────────────
    let probe = probe_ch();
    let ch_binary = probe.ch_binary.expect("is_ready guarantees ch_binary");
    let cid = next_cid();

    let vm_config = ChVmConfig {
        cid,
        ch_binary,
        kernel: ch_vmlinux_path().expect("vmlinux path"),
        initrd: ch_initrd_path().expect("initrd path"),
        memory_mb: 256,
        cpu_count: 1,
        shared_dir: None,
    };

    // ── Boot VM ──────────────────────────────────────────────────────────────
    let t_boot_start = Instant::now();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut vm = rt.block_on(ChVm::spawn(vm_config)).expect("VM spawn");
    let t_boot = t_boot_start.elapsed();
    println!("VM boot: {t_boot:.2?}");

    // ── Poll guest-agent ping ────────────────────────────────────────────────
    let rpc = GuestRpc::new(vm.vsock_socket.clone(), 1024);
    let guest_ready = rt.block_on(async {
        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        loop {
            match rpc.ping().await {
                Ok(()) => {
                    println!("guest-agent ready: {:.2?}", start.elapsed());
                    return Ok(());
                }
                Err(e) => {
                    if start.elapsed() >= timeout {
                        return Err(format!(
                            "guest-agent did not respond within {:.0}s: {e}",
                            timeout.as_secs_f32()
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });
    guest_ready.expect("guest-agent ready");

    // ── Open PTY with /bin/sh ────────────────────────────────────────────────
    let t_pty_start = Instant::now();
    let mut pty = rt
        .block_on(rpc.open_pty(vec!["/bin/sh".into()], 80, 24))
        .expect("open_pty");
    println!("PTY opened: {:.2?}", t_pty_start.elapsed());

    // ── Write echo command ───────────────────────────────────────────────────
    rt.block_on(pty.write_stdin(b"echo hi\n")).expect("write echo");

    // ── Drain stdout until we see "hi" ──────────────────────────────────────
    let mut stdout_acc = String::new();
    let mut found_hi = false;

    let result = rt.block_on(async {
        let timeout_duration = Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout_duration;

        while tokio::time::Instant::now() < deadline {
            let timeout_remaining = deadline.saturating_duration_since(tokio::time::Instant::now());

            match tokio::time::timeout(timeout_remaining, pty.read_frame()).await {
                Ok(Ok(Some(PtyFrame::Stdout { data }))) => {
                    print!("{}", data);
                    stdout_acc.push_str(&data);
                    if stdout_acc.contains("hi") {
                        return Ok(true);
                    }
                }
                Ok(Ok(Some(PtyFrame::Error { msg }))) => {
                    return Err(format!("PTY error: {msg}"));
                }
                Ok(Ok(Some(PtyFrame::Exit { code }))) => {
                    return Err(format!("PTY exited unexpectedly with code {code}"));
                }
                Ok(Ok(None)) => {
                    return Ok(false);
                }
                Ok(Err(e)) => {
                    return Err(format!("read_frame error: {e}"));
                }
                Err(_timeout) => {
                    eprintln!("read_frame timed out waiting for 'hi' in output");
                    return Ok(false);
                }
            }
        }
        Ok(false)
    });

    match result {
        Ok(true) => found_hi = true,
        Ok(false) => {}
        Err(e) => panic!("{e}"),
    }

    assert!(found_hi, "expected to see 'hi' in output, got: {stdout_acc:?}");
    println!("\nSaw 'hi' in PTY output");

    // ── Write exit command ───────────────────────────────────────────────────
    rt.block_on(pty.write_stdin(b"exit\n")).expect("write exit");

    // ── Wait for exit frame ──────────────────────────────────────────────────
    let exit_code = rt.block_on(async {
        let timeout_duration = Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout_duration;

        while tokio::time::Instant::now() < deadline {
            let timeout_remaining = deadline.saturating_duration_since(tokio::time::Instant::now());

            match tokio::time::timeout(timeout_remaining, pty.read_frame()).await {
                Ok(Ok(Some(PtyFrame::Stdout { data }))) => {
                    print!("{}", data);
                }
                Ok(Ok(Some(PtyFrame::Exit { code }))) => {
                    return Ok(Some(code));
                }
                Ok(Ok(Some(PtyFrame::Error { msg }))) => {
                    return Err(format!("PTY error: {msg}"));
                }
                Ok(Ok(None)) => {
                    return Ok(None);
                }
                Ok(Err(e)) => {
                    return Err(format!("read_frame error: {e}"));
                }
                Err(_timeout) => {
                    eprintln!("read_frame timed out waiting for exit frame");
                    return Ok(None);
                }
            }
        }
        Ok(None)
    });

    let exit_code = match exit_code {
        Ok(code) => code,
        Err(e) => panic!("{e}"),
    };

    println!("PTY exit code: {exit_code:?}");
    assert_eq!(exit_code, Some(0), "expected exit code 0");

    let elapsed = t_pty_start.elapsed();
    println!("PTY session elapsed: {elapsed:.2?}");

    // ── Shutdown ─────────────────────────────────────────────────────────────
    rt.block_on(vm.shutdown(Duration::from_secs(2))).expect("VM shutdown");
}
