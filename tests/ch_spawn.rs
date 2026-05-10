//! Integration test: spawn a cloud-hypervisor VM and shut it down.
//!
//! # Prerequisites
//!
//! - `/dev/kvm` accessible
//! - `/dev/vhost-vsock` present
//! - `bin/cloud-hypervisor/current/bin/cloud-hypervisor` available
//! - `bin/ch-vmlinux/current/bin/vmlinux` available
//! - `bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz` built (`make ch-initrd`)
//!
//! # Running
//!
//! ```sh
//! cargo test -p tokimo-package-sandbox -- --ignored ch_spawn
//! ```
//!
//! The test is `#[ignore]` by default because it requires KVM hardware
//! access and built initrd artefacts that are not present in CI.

#![cfg(target_os = "linux")]

use std::time::Duration;

use tokimo_package_sandbox::ch::vmm::{ChVm, ChVmConfig, ch_initrd_path, ch_vmlinux_path, next_cid};
use tokimo_package_sandbox::ch_probe::probe_ch;

/// Skip helper: returns a descriptive string if the host cannot run CH VMs.
fn skip_reason() -> Option<String> {
    let probe = probe_ch();
    if !probe.is_ready() {
        return Some(format!("host not ready for cloud-hypervisor:\n{}", probe.report()));
    }
    let initrd = match ch_initrd_path() {
        Ok(p) => p,
        Err(e) => return Some(format!("ch_initrd_path error: {e}")),
    };
    if !initrd.exists() {
        return Some(format!(
            "initrd not found at '{}' — run: make ch-initrd",
            initrd.display()
        ));
    }
    None
}

/// Spawn a cloud-hypervisor VM, verify the API socket appeared, then shut
/// it down and verify the child exited and sockets were cleaned up.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires KVM + cloud-hypervisor binary + initrd (make ch-initrd)"]
async fn ch_spawn_and_shutdown() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let probe = probe_ch();
    let ch_binary = probe.ch_binary.clone().expect("probe guarantees Some when ready");
    let kernel = ch_vmlinux_path().expect("vmlinux path");
    let initrd = ch_initrd_path().expect("initrd path");
    let cid = next_cid();

    let config = ChVmConfig {
        cid,
        ch_binary,
        kernel,
        initrd,
        memory_mb: 256,
        cpu_count: 1,
        shared_dir: None,
        network: None,
    };

    let api_socket = std::path::PathBuf::from(format!("/tmp/tokimo-ch-api-{cid}.sock"));
    let vsock_socket = std::path::PathBuf::from(format!("/tmp/tokimo-ch-vsock-{cid}.sock"));

    let mut vm = ChVm::spawn(config).await.expect("VM spawn must succeed");

    // API socket must exist after spawn.
    assert!(api_socket.exists(), "API socket must exist after spawn");
    assert!(vm.is_alive(), "child must be alive after spawn");

    // Shut down.
    vm.shutdown(Duration::from_secs(3))
        .await
        .expect("shutdown must succeed");

    // Child must have exited and sockets cleaned up.
    assert!(!vm.is_alive(), "child must have exited after shutdown");
    assert!(!api_socket.exists(), "API socket must be cleaned up");
    assert!(!vsock_socket.exists(), "vsock socket must be cleaned up");
}
