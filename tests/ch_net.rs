//! Integration test: Cloud Hypervisor guest networking via passt.
//!
//! Spawns a real cloud-hypervisor microVM with networking enabled, verifies
//! guest route/DHCP evidence from `/proc/net/route` or `ip route`, and fetches
//! a small external page through `/bin/wget`.
//!
//! # Prerequisites
//!
//! - `/dev/kvm` accessible (user in `kvm` group)
//! - `/dev/vhost-vsock` present
//! - `bin/cloud-hypervisor/current/bin/cloud-hypervisor` available
//! - `bin/passt/current/bin/passt` available
//! - `bin/ch-vmlinux/current/bin/vmlinux` available
//! - `bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz` built (`make ch-initrd`)
//!
//! # Running
//!
//! ```sh
//! cargo test -p tokimo-package-sandbox -- --ignored ch_net_passt_smoke
//! ```

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::ch::rpc::{GuestRpc, Response};
use tokimo_package_sandbox::ch::vmm::{
    ChVm, ChVmConfig, NetworkConfig, ch_initrd_path, ch_vmlinux_path, locate_project_root, next_cid,
};
use tokimo_package_sandbox::ch_probe::probe_ch;

/// Returns a skip reason string if the host cannot run CH VMs with passt networking.
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

    let passt_binary = passt_path();
    if !passt_binary.exists() {
        return Some(format!(
            "passt binary not found at '{}' — run: make passt",
            passt_binary.display()
        ));
    }

    None
}

fn passt_path() -> PathBuf {
    let root = locate_project_root().expect("cannot locate project root");
    root.join("bin/passt/current/bin/passt")
}

fn wait_for_guest_agent(rt: &tokio::runtime::Runtime, rpc: &GuestRpc) {
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
}

#[derive(Debug)]
struct CommandResult {
    stdout: String,
    exit_code: Option<i32>,
    error: Option<String>,
}

fn collect_command_result(command_name: &str, frames: Vec<Response>) -> CommandResult {
    let mut stdout_acc = String::new();
    let mut exit_code: Option<i32> = None;
    let mut error: Option<String> = None;

    for frame in frames {
        match frame {
            Response::Stdout { data } => {
                stdout_acc.push_str(&data);
            }
            Response::Stderr { data } => {
                eprintln!("{command_name} stderr: {data}");
            }
            Response::Exit { code } => {
                exit_code = Some(code);
            }
            Response::Error { msg } => {
                error = Some(msg);
            }
            _ => {}
        }
    }

    CommandResult {
        stdout: stdout_acc,
        exit_code,
        error,
    }
}

fn run_guest_command(rt: &tokio::runtime::Runtime, rpc: &GuestRpc, command_name: &str, argv: &[&str]) -> CommandResult {
    let frames = rt
        .block_on(rpc.spawn_command(&argv.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>()))
        .unwrap_or_else(|e| panic!("spawn_command {command_name}: {e}"));
    collect_command_result(command_name, frames)
}

fn has_proc_route_evidence(stdout: &str) -> bool {
    stdout.lines().skip(1).any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 3 && fields[0] == "eth0" && (fields[1] == "00000000" || fields[2] != "00000000")
    })
}

fn has_ip_route_evidence(stdout: &str) -> bool {
    stdout
        .lines()
        .any(|line| line.contains("default") || line.contains(" dev eth0"))
}

fn has_fib_trie_evidence(stdout: &str) -> bool {
    stdout.contains("0.0.0.0") && (stdout.contains("192.168.") || stdout.contains("10.") || stdout.contains("172."))
}

fn wait_for_route_evidence(rt: &tokio::runtime::Runtime, rpc: &GuestRpc) -> String {
    let start = Instant::now();
    let timeout = Duration::from_secs(8);
    let mut last_output = String::new();

    loop {
        for (label, argv, check) in [
            (
                "cat /proc/net/route",
                &["/bin/cat", "/proc/net/route"][..],
                has_proc_route_evidence as fn(&str) -> bool,
            ),
            (
                "busybox cat /proc/net/route",
                &["/bin/busybox", "cat", "/proc/net/route"][..],
                has_proc_route_evidence as fn(&str) -> bool,
            ),
            (
                "ip route",
                &["/bin/ip", "route"][..],
                has_ip_route_evidence as fn(&str) -> bool,
            ),
            (
                "busybox ip route",
                &["/bin/busybox", "ip", "route"][..],
                has_ip_route_evidence as fn(&str) -> bool,
            ),
            (
                "cat /proc/net/fib_trie",
                &["/bin/cat", "/proc/net/fib_trie"][..],
                has_fib_trie_evidence as fn(&str) -> bool,
            ),
            (
                "busybox cat /proc/net/fib_trie",
                &["/bin/busybox", "cat", "/proc/net/fib_trie"][..],
                has_fib_trie_evidence as fn(&str) -> bool,
            ),
        ] {
            let result = run_guest_command(rt, rpc, label, argv);
            if let Some(error) = &result.error {
                last_output.push_str(&format!("{label}: guest error: {error}\n"));
                continue;
            }
            if result.exit_code != Some(0) {
                last_output.push_str(&format!("{label}: exit {:?}\n", result.exit_code));
                continue;
            }

            last_output.push_str(&format!("{label}:\n{}\n", result.stdout));
            if check(&result.stdout) {
                return format!("{label}:\n{}", result.stdout);
            }
        }

        if start.elapsed() >= timeout {
            panic!(
                "guest route evidence did not appear within {:.0}s; last outputs:\n{}",
                timeout.as_secs_f32(),
                last_output
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wget_argv() -> Vec<&'static [&'static str]> {
    vec![
        &["/bin/wget", "-qO-", "-T", "5", "http://example.com"],
        &["/bin/busybox", "wget", "-qO-", "-T", "5", "http://example.com"],
    ]
}

/// Test passt networking: boot a networked guest, inspect kernel route state,
/// and fetch example.com from inside the guest.
///
/// The test is `#[ignore]` because it requires KVM hardware access, a built
/// initrd, cloud-hypervisor, and passt binaries — not available in standard CI.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires KVM + cloud-hypervisor + passt + initrd (make ch-initrd)"]
fn ch_net_passt_smoke() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP: {reason}");
        return;
    }

    // ── Construct VM config ──────────────────────────────────────────────────
    let probe = probe_ch();
    let ch_binary = probe.ch_binary.expect("is_ready guarantees ch_binary");
    let cid = next_cid();
    let passt_binary = passt_path();
    assert!(
        passt_binary.exists(),
        "passt binary should exist at '{}'",
        passt_binary.display()
    );

    let vm_config = ChVmConfig {
        cid,
        ch_binary,
        kernel: ch_vmlinux_path().expect("vmlinux path"),
        initrd: ch_initrd_path().expect("initrd path"),
        memory_mb: 256,
        cpu_count: 1,
        shared_dir: None,
        network: Some(NetworkConfig {
            passt_binary,
            mac_addr: None,
        }),
    };

    // ── Boot VM ──────────────────────────────────────────────────────────────
    let t_boot_start = Instant::now();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut vm = rt.block_on(ChVm::spawn(vm_config)).expect("VM spawn");
    let t_boot = t_boot_start.elapsed();
    println!("VM boot: {t_boot:.2?}");

    let test_result = catch_unwind(AssertUnwindSafe(|| {
        // ── Poll guest-agent ping ────────────────────────────────────────────
        let rpc = GuestRpc::new(vm.vsock_socket.clone(), 1024);
        wait_for_guest_agent(&rt, &rpc);

        // ── Verify DHCP/route evidence ───────────────────────────────────────
        let t_route_start = Instant::now();
        let route_evidence = wait_for_route_evidence(&rt, &rpc);
        let t_route = t_route_start.elapsed();
        println!("route evidence elapsed: {t_route:.2?}");
        println!("guest route evidence:\n{route_evidence}");

        // ── Fetch through guest network ──────────────────────────────────────
        let t_wget_start = Instant::now();
        let mut wget_result = None;
        for argv in wget_argv() {
            let label = argv.join(" ");
            let result = run_guest_command(&rt, &rpc, &label, argv);
            if result.error.is_none() && result.exit_code == Some(0) {
                wget_result = Some((label, result));
                break;
            }
            eprintln!(
                "wget candidate failed: {label}: exit={:?} error={:?}",
                result.exit_code, result.error
            );
        }
        let t_wget = t_wget_start.elapsed();
        println!("wget example.com elapsed: {t_wget:.2?}");

        let (wget_label, wget_result) = wget_result.expect("a wget command should succeed");
        println!("wget command: {wget_label}");
        println!("wget stdout bytes: {}", wget_result.stdout.len());
        assert!(!wget_result.stdout.is_empty(), "wget stdout should be non-empty");
        if !wget_result.stdout.contains("Example Domain") {
            eprintln!("WARN: wget stdout did not contain 'Example Domain'");
        }
    }));

    // ── Shutdown ─────────────────────────────────────────────────────────────
    let shutdown_result = rt.block_on(vm.shutdown(Duration::from_secs(2)));
    if let Err(payload) = test_result {
        let _ = shutdown_result;
        resume_unwind(payload);
    }
    shutdown_result.expect("VM shutdown");
}
