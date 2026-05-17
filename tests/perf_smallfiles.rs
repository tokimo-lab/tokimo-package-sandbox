//! Microbench for FUSE small-file performance.
//! Run with: PATH=$PWD/target/debug:$PATH SANDBOX_BACKEND={bwrap|ch} \
//!          cargo test --test perf_smallfiles --release -- --nocapture
mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::Sandbox;

const BENCH: &str = include_str!("../tests/perf_smallfiles_bench.sh");

#[test]
#[ignore = "perf bench: opt-in"]
fn perf_smallfiles() {
    let label = "perfsf";
    let ws = workspace_dir(label);
    std::fs::write(ws.join("bench.sh"), BENCH).unwrap();

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _g = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let backend = std::env::var("SANDBOX_BACKEND").unwrap_or_else(|_| "default".into());
    println!("\n=== BACKEND: {} ===", backend);
    println!("--- FUSE share (/tmp/tokimo-share) ---");
    sb.write_stdin(
        &shell,
        b"bash /tmp/tokimo-share/bench.sh /tmp/tokimo-share/bench 500 && echo BENCH_FUSE_DONE\n",
    )
    .unwrap();
    let out = drain_until(&rx, &shell, "BENCH_FUSE_DONE", Duration::from_secs(180));
    println!("{}", out);

    println!("--- guest tmpfs (/tmp) ---");
    sb.write_stdin(
        &shell,
        b"bash /tmp/tokimo-share/bench.sh /tmp/guest_bench 500 && echo BENCH_TMPFS_DONE\n",
    )
    .unwrap();
    let out = drain_until(&rx, &shell, "BENCH_TMPFS_DONE", Duration::from_secs(180));
    println!("{}", out);

    sb.stop_vm().ok();
}
