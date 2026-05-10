//! Integration test: virtiofs shared directory access in a CH microVM.
//!
//! Spawns a real cloud-hypervisor microVM with a virtiofs share, creates a
//! test file on the host, and reads it from the guest at `/mnt/host.txt`.
//!
//! # Prerequisites
//!
//! - `/dev/kvm` accessible (user in `kvm` group)
//! - `/dev/vhost-vsock` present
//! - `bin/cloud-hypervisor/current/bin/cloud-hypervisor` available
//! - `bin/virtiofsd/current/virtiofsd` available
//! - `bin/ch-vmlinux/current/bin/vmlinux` available
//! - `bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz` built (`make ch-initrd`)
//!
//! # Running
//!
//! ```sh
//! cargo test -p tokimo-package-sandbox -- --ignored ch_virtiofs_round_trip
//! ```

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::ch::rpc::GuestRpc;
use tokimo_package_sandbox::ch::vmm::{ChVm, ChVmConfig, ch_initrd_path, ch_vmlinux_path, next_cid, virtiofsd_path};
use tokimo_package_sandbox::ch_probe::probe_ch;

/// Returns a skip reason string if the host cannot run CH VMs with virtiofs.
fn skip_reason() -> Option<String> {
    // Check if /dev/kvm can actually be opened with read/write access.
    // probe_ch() only checks if the file exists (metadata succeeds), but
    // cloud-hypervisor needs to open it for reading and writing.
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
    if !probe.virtiofsd_available {
        return Some("virtiofsd binary not found — run: make virtiofsd".to_string());
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
    match virtiofsd_path() {
        Err(e) => return Some(format!("virtiofsd_path error: {e}")),
        Ok(p) if !p.exists() => {
            return Some(format!(
                "virtiofsd not found at '{}' — run: make virtiofsd",
                p.display()
            ));
        }
        Ok(_) => {}
    }
    None
}

/// Test virtiofs: create a host file, spawn VM with shared directory,
/// read the file from /mnt in the guest, verify content.
///
/// The test is `#[ignore]` because it requires KVM hardware access, a built
/// initrd, cloud-hypervisor, and virtiofsd binaries — not available in standard CI.
#[test]
#[ignore = "requires KVM + cloud-hypervisor + virtiofsd + initrd (make ch-initrd)"]
fn ch_virtiofs_round_trip() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP: {reason}");
        return;
    }

    // ── Create test share directory ──────────────────────────────────────────
    // Use target directory to avoid /tmp constraint, unique name with PID
    let test_dir = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("test-virtiofs-{}", std::process::id()));
    std::fs::create_dir_all(&test_dir).expect("create test share dir");

    // Write test file
    let test_content = "from-host";
    std::fs::write(test_dir.join("host.txt"), test_content).expect("write host.txt");

    // Clean up on panic or return
    let _cleanup = CleanupDir(test_dir.clone());

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
        shared_dir: Some(test_dir.clone()),
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

    // ── Query mount status ───────────────────────────────────────────────────
    let mounted = rt.block_on(rpc.query_mount("/mnt")).expect("query_mount");
    println!("/mnt mounted: {mounted}");
    assert!(mounted, "/mnt should be mounted via virtiofs");

    // ── Read file from guest ─────────────────────────────────────────────────
    let t_read_start = Instant::now();
    let frames = rt
        .block_on(rpc.spawn_command(&["/bin/cat".into(), "/mnt/host.txt".into()]))
        .expect("spawn_command cat");
    let t_read = t_read_start.elapsed();
    println!("cat /mnt/host.txt elapsed: {t_read:.2?}");

    // ── Parse output ─────────────────────────────────────────────────────────
    let mut stdout_acc = String::new();
    let mut exit_code: Option<i32> = None;

    for frame in frames {
        match frame {
            tokimo_package_sandbox::ch::rpc::Response::Stdout { data } => {
                stdout_acc.push_str(&data);
            }
            tokimo_package_sandbox::ch::rpc::Response::Stderr { data } => {
                eprintln!("cat stderr: {data}");
            }
            tokimo_package_sandbox::ch::rpc::Response::Exit { code } => {
                exit_code = Some(code);
            }
            tokimo_package_sandbox::ch::rpc::Response::Error { msg } => {
                panic!("guest error: {msg}");
            }
            _ => {}
        }
    }

    // ── Assert ───────────────────────────────────────────────────────────────
    assert_eq!(stdout_acc.trim(), test_content, "stdout should match host file content");
    assert_eq!(exit_code, Some(0), "exit code should be 0");

    // ── Shutdown ─────────────────────────────────────────────────────────────
    rt.block_on(vm.shutdown(Duration::from_secs(2))).expect("VM shutdown");
}

/// RAII guard to clean up test directory on drop.
struct CleanupDir(std::path::PathBuf);

impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
