//! End-to-end test for dynamic Plan9 share add/remove.
//!
//! Run as: `cargo run --example dynamic_mount`
//!
//! Requires `tokimo-sandbox-svc` to be running.
//!
//! Scenario:
//! 1. Configure the VM with a single boot-time share `host`.
//! 2. Start it, verify `/mnt/host` works and `/mnt/dynA`, `/mnt/dynB` are absent.
//! 3. `add_plan9_share` for `dynA` → assert `/mnt/dynA` is readable.
//! 4. `add_plan9_share` for `dynB` → assert both are visible.
//! 5. `remove_plan9_share("dynA")` → assert `/mnt/dynA` gone, `/mnt/dynB` still works.
//! 6. Verify `remove_plan9_share("host")` is rejected (boot-time share).
//! 7. Stop.

use std::path::PathBuf;
use std::time::Instant;

use tokimo_package_sandbox::{
    ConfigureParams, ExecOpts, NetworkPolicy, Plan9Share, Sandbox,
};

fn banner(s: &str) {
    println!("\n========== {} ==========", s);
}

fn must_run(sb: &Sandbox, label: &str, argv: &[&str]) -> (i32, String, String) {
    match sb.exec(argv, ExecOpts::default()) {
        Ok(r) => {
            let out = r.stdout_str();
            let err = r.stderr_str();
            println!(
                "[{label}] exit={} stdout={:?} stderr={:?}",
                r.exit_code,
                out.lines().next().unwrap_or("").trim(),
                err.lines().next().unwrap_or("").trim()
            );
            (r.exit_code, out, err)
        }
        Err(e) => {
            panic!("[{label}] exec failed: {e}");
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let dir_host = cwd.join("examples");
    let dir_a = cwd.join("target").join("dynA");
    let dir_b = cwd.join("target").join("dynB");
    std::fs::create_dir_all(&dir_a)?;
    std::fs::create_dir_all(&dir_b)?;
    std::fs::write(dir_a.join("a.txt"), b"hello-from-A\n")?;
    std::fs::write(dir_b.join("b.txt"), b"hello-from-B\n")?;

    println!("dir_host = {}", dir_host.display());
    println!("dir_a    = {}", dir_a.display());
    println!("dir_b    = {}", dir_b.display());

    banner("connect + configure + start");
    let sb = Sandbox::connect()?;
    sb.configure(ConfigureParams {
        user_data_name: "dynamic-mount-test".into(),
        memory_mb: 2048,
        cpu_count: 2,
        plan9_shares: vec![Plan9Share {
            name: "host".into(),
            host_path: dir_host.clone(),
            guest_path: PathBuf::from("/mnt/host"),
            read_only: false,
        }],
        network: NetworkPolicy::AllowAll,
        ..Default::default()
    })?;
    sb.create_vm()?;
    let t = Instant::now();
    sb.start_vm()?;
    println!("startVm OK ({}ms)", t.elapsed().as_millis());

    let mut pass = 0u32;
    let mut total = 0u32;

    banner("baseline: /mnt/host visible, /mnt/dynA absent");
    total += 1;
    let (rc, _, _) = must_run(&sb, "ls-host", &["ls", "/mnt/host"]);
    if rc == 0 { pass += 1; }
    total += 1;
    let (rc, _, _) = must_run(&sb, "ls-dynA-pre", &["ls", "/mnt/dynA"]);
    if rc != 0 { pass += 1; } // expected to fail (not yet mounted)

    banner("add_plan9_share dynA");
    total += 1;
    sb.add_plan9_share(Plan9Share {
        name: "dynA".into(),
        host_path: dir_a.clone(),
        guest_path: PathBuf::from("/mnt/dynA"),
        read_only: false,
    })?;
    let (rc, out, _) = must_run(&sb, "cat-dynA", &["cat", "/mnt/dynA/a.txt"]);
    if rc == 0 && out.trim() == "hello-from-A" { pass += 1; }

    banner("add_plan9_share dynB (read-only)");
    total += 1;
    sb.add_plan9_share(Plan9Share {
        name: "dynB".into(),
        host_path: dir_b.clone(),
        guest_path: PathBuf::from("/mnt/dynB"),
        read_only: true,
    })?;
    let (rc, out, _) = must_run(&sb, "cat-dynB", &["cat", "/mnt/dynB/b.txt"]);
    if rc == 0 && out.trim() == "hello-from-B" { pass += 1; }

    // dynA still works, both visible
    total += 1;
    let (rc1, _, _) = must_run(&sb, "ls-dynA", &["ls", "/mnt/dynA"]);
    let (rc2, _, _) = must_run(&sb, "ls-dynB", &["ls", "/mnt/dynB"]);
    if rc1 == 0 && rc2 == 0 { pass += 1; }

    banner("read-only enforcement on dynB");
    total += 1;
    let r = sb.exec(
        &["sh", "-c", "echo x > /mnt/dynB/should-fail.txt; echo rc=$?"],
        ExecOpts::default(),
    )?;
    let so = r.stdout_str();
    println!("dynB write attempt: {}", so.trim());
    if !so.trim().ends_with("rc=0") { pass += 1; }

    banner("remove_plan9_share dynA");
    total += 1;
    sb.remove_plan9_share("dynA")?;
    let (rc, _, _) = must_run(&sb, "ls-dynA-after", &["ls", "/mnt/dynA"]);
    let (rc_b, _, _) = must_run(&sb, "ls-dynB-after", &["ls", "/mnt/dynB"]);
    if rc != 0 && rc_b == 0 { pass += 1; }

    banner("remove of boot-time share rejected");
    total += 1;
    match sb.remove_plan9_share("host") {
        Ok(_) => println!("FAIL: boot-time share removed unexpectedly"),
        Err(e) => {
            println!("expected error: {e}");
            pass += 1;
        }
    }

    banner("remove of unknown share rejected");
    total += 1;
    match sb.remove_plan9_share("does-not-exist") {
        Ok(_) => println!("FAIL: unknown share removed unexpectedly"),
        Err(e) => {
            println!("expected error: {e}");
            pass += 1;
        }
    }

    banner("ls before mounting current project src");
    total += 1;
    let (rc, _, _) = must_run(&sb, "ls-src-pre", &["ls", "/mnt/src"]);
    if rc != 0 { pass += 1; } // not mounted yet -> ENOENT

    banner("mount current project root at /mnt/src (read-only)");
    sb.add_plan9_share(Plan9Share {
        name: "src".into(),
        host_path: cwd.clone(),
        guest_path: PathBuf::from("/mnt/src"),
        read_only: true,
    })?;
    println!("mounted host={} -> /mnt/src (ro)", cwd.display());

    banner("ls after mounting — should show project files");
    total += 1;
    let (rc, out, _) = must_run(&sb, "ls-src", &["ls", "/mnt/src"]);
    if rc == 0 && out.contains("Cargo.toml") && out.contains("src") {
        pass += 1;
    }

    total += 1;
    let r = sb.exec(
        &["sh", "-c", "head -1 /mnt/src/Cargo.toml"],
        ExecOpts::default(),
    )?;
    let head = r.stdout_str();
    println!("[head-cargo-toml] exit={} stdout={:?}", r.exit_code, head.trim());
    if r.exit_code == 0 && !head.is_empty() { pass += 1; }

    total += 1;
    let r = sb.exec(
        &["sh", "-c", "wc -l /mnt/src/src/lib.rs"],
        ExecOpts::default(),
    )?;
    println!("[wc-lib-rs] exit={} stdout={:?}", r.exit_code, r.stdout_str().trim());
    if r.exit_code == 0 { pass += 1; }

    sb.remove_plan9_share("src")?;
    println!("unmounted /mnt/src");

    banner("stop");
    sb.stop_vm()?;
    println!("stopVm OK");

    // cleanup
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    println!("\n=== {pass}/{total} dynamic-mount checks passed ===");
    if pass != total {
        std::process::exit(1);
    }
    Ok(())
}
