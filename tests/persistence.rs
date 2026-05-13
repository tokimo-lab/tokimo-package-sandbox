mod common;

/// Rootfs persistence test (Windows / HCS only).
///
/// Verifies that writes inside the guest ext4 rootfs VHDX survive a full
/// VM teardown and restart when the rootfs is a *persistent* target.
///
/// Design notes
/// ------------
/// * `stop_vm()` is called explicitly to exercise the graceful-shutdown
///   path added to `teardown_session` (HcsShutdownComputeSystem before
///   HcsTerminateComputeSystem). The `owner_pid_waiter` path (Ctrl+C /
///   parent-death) calls the exact same `teardown_session` function, so
///   this test covers both teardown entry points.
/// * Each test run uses a unique `vm_dir` (`.vm/run/persist-test-<pid>/`).
///   Before run 1 we explicitly create that directory and copy
///   `.vm/base/rootfs.vhdx` into it so the VHDX is a fresh writable
///   clone owned solely by this test invocation.  On run 2 the same VHDX
///   already contains the writes from run 1 — that is what we verify.
/// * We deliberately do **not** touch `.vm/base` or any path under
///   `F:\tokimo\.data\` so that production/developer artifacts are safe.
#[cfg(target_os = "windows")]
mod windows_persistence {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::common::{SandboxGuard, drain_until};
    use tokimo_package_sandbox::{ConfigureParams, Mount, NetworkPolicy, Sandbox};

    /// Returns a per-process-unique directory inside the submodule's
    /// `.vm/run/` scratch area.  Using the PID keeps parallel CI jobs
    /// isolated while remaining stable for the two VM runs within a
    /// single test invocation.
    fn persist_vm_dir() -> PathBuf {
        PathBuf::from(".vm/run").join(format!("persist-test-{}", std::process::id()))
    }

    fn canonical_existing_path(path: &Path, label: &str) -> PathBuf {
        path.canonicalize()
            .unwrap_or_else(|_| panic!("canonicalize {label}: {}", path.display()))
    }

    fn persist_config() -> ConfigureParams {
        let base_rootfs = canonical_existing_path(Path::new(".vm/base"), "base rootfs directory");
        let vm_dir = canonical_existing_path(&persist_vm_dir(), "test vm_dir");
        // The workspace mount is required by the service validator; we
        // point it at the vm_dir itself — its host-side content is
        // irrelevant for this test.
        let ws_host = vm_dir.clone();
        ConfigureParams {
            user_data_name: "persist-test".into(),
            base_rootfs,
            vm_dir,
            memory_mb: 1024,
            cpu_count: 2,
            mounts: vec![Mount {
                name: "ws".into(),
                host_path: ws_host,
                guest_path: "/tmp/tokimo-share".into(),
                read_only: false,
                create_host_dir: false,
            }],
            network: NetworkPolicy::Blocked,
            // Stable session_id — same key used for both VM runs so the
            // service's session registry reconnects to the same slot.
            session_id: format!("persist-{}", std::process::id()),
            ..Default::default()
        }
    }

    #[test]
    fn rootfs_writes_persist_across_vm_restart_then_terminate() {
        // Skip if the base rootfs is absent (e.g. CI without a VM image).
        if !std::path::Path::new(".vm/base/rootfs.vhdx").exists() {
            eprintln!(
                "persistence test skipped: .vm/base/rootfs.vhdx not found; \
                 set up the base VM image to run this test"
            );
            return;
        }

        // Setup: create a fresh scratch directory and copy the base VHDX into
        // it so this test owns a completely isolated writable rootfs.
        // Remove any leftover from a previously interrupted run first.
        let vm_dir = persist_vm_dir();
        if vm_dir.exists() {
            std::fs::remove_dir_all(&vm_dir).expect("remove leftover vm_dir");
        }
        std::fs::create_dir_all(&vm_dir).expect("create vm_dir");
        std::fs::copy(".vm/base/rootfs.vhdx", vm_dir.join("rootfs.vhdx"))
            .expect("copy base rootfs.vhdx into test vm_dir");

        const SENTINEL_CONTENT: &str = "tokimo-persist-ok-3F8A";
        const SENTINEL_PATH: &str = "/home/tokimo/tokimo_persist_test.txt";
        const WRITE_DONE: &str = "PERSIST_WRITE_DONE_7E2C";
        const READ_DONE: &str = "PERSIST_READ_DONE_9B1D";

        // ── Run 1: write sentinel into the rootfs, then stop gracefully ──

        let sb1 = Sandbox::connect().expect("connect (run 1)");
        sb1.configure(persist_config()).expect("configure (run 1)");
        let rx1 = sb1.subscribe().expect("subscribe (run 1)");
        sb1.start_vm().expect("start_vm (run 1)");
        let _guard1 = SandboxGuard(sb1.clone());

        let shell1 = sb1.shell_id().expect("shell_id (run 1)");

        // Write sentinel file under /home/tokimo/ (ensure parent dir exists)
        // then flush all dirty buffers to the VHDX before stopping.
        sb1.write_stdin(
            &shell1,
            format!(
                "mkdir -p /home/tokimo && echo '{}' > {} && sync && echo {}\n",
                SENTINEL_CONTENT, SENTINEL_PATH, WRITE_DONE
            )
            .as_bytes(),
        )
        .expect("write_stdin (run 1)");

        let out1 = drain_until(&rx1, &shell1, WRITE_DONE, Duration::from_secs(30));
        assert!(
            out1.contains(WRITE_DONE),
            "sentinel write+sync did not complete within timeout; got: {out1:?}"
        );

        // stop_vm() calls teardown_session → HcsShutdownComputeSystem (graceful)
        // → HcsTerminateComputeSystem (fallback) → HcsCloseComputeSystem →
        // drop VhdxLease.  The VM is fully down and the VHDX is closed before
        // this call returns.
        sb1.stop_vm().expect("stop_vm (run 1)");
        drop(_guard1); // guard no-ops since stop_vm already called

        // Sanity: the VHDX file must still exist (persistent, not deleted).
        let vhdx_path = persist_vm_dir().join("rootfs.vhdx");
        assert!(
            vhdx_path.exists(),
            "rootfs.vhdx was deleted after stop_vm — expected persistent lease: {}",
            vhdx_path.display()
        );

        // ── Run 2: restart with the same vm_dir, read back the sentinel ──

        let sb2 = Sandbox::connect().expect("connect (run 2)");
        sb2.configure(persist_config()).expect("configure (run 2)");
        let rx2 = sb2.subscribe().expect("subscribe (run 2)");
        sb2.start_vm().expect("start_vm (run 2)");
        let _guard2 = SandboxGuard(sb2.clone());

        let shell2 = sb2.shell_id().expect("shell_id (run 2)");

        sb2.write_stdin(
            &shell2,
            format!("cat {} && echo {}\n", SENTINEL_PATH, READ_DONE).as_bytes(),
        )
        .expect("write_stdin (run 2)");

        let out2 = drain_until(&rx2, &shell2, READ_DONE, Duration::from_secs(30));

        sb2.stop_vm().ok();
        drop(_guard2);

        // Clean up the scratch directory now that the test is done.
        std::fs::remove_dir_all(&vm_dir).ok();

        assert!(
            out2.contains(SENTINEL_CONTENT),
            "sentinel content '{SENTINEL_CONTENT}' not found after VM restart; got: {out2:?}"
        );
    }
}
