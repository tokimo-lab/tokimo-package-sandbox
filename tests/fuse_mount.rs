mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, workspace_dir};
use tokimo_package_sandbox::{Mount, Sandbox};

#[test]
fn fuse_host_file_visible_in_guest() {
    const FNAME: &str = "tokimo_sentinel.txt";
    const BODY: &str = "SENTINEL_FROM_HOST_5C9D";

    // We need to write the file on the host *before* configure picks up
    // the workspace path. config(label) creates a per-label tmp dir and
    // shares it as /work — write the sentinel into that exact dir.
    let label = "p9visible";
    let host_path = workspace_dir(label).join(FNAME);
    std::fs::write(&host_path, BODY).expect("write sentinel on host");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(&shell, format!("cat /work/{FNAME}\n").as_bytes())
        .unwrap();

    let captured = drain_until(&rx, &shell, BODY, Duration::from_secs(30));
    sb.stop_vm().ok();
    let _ = std::fs::remove_file(&host_path);

    assert!(
        captured.contains(BODY),
        "host sentinel not visible in guest. captured: {captured:?}"
    );
}

#[test]
fn fuse_dynamic_add_remove() {
    const FNAME: &str = "extra_sentinel.txt";
    const BODY: &str = "DYNAMIC_5E7C_HOST";

    let label = "p9dyn";
    let extra = workspace_dir(&format!("{label}-extra"));
    std::fs::write(extra.join(FNAME), BODY).expect("write sentinel");

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // 1. Before add: /extra is empty / nonexistent.
    sb.write_stdin(&shell, b"ls /extra 2>&1 | head -1; echo PRE_DONE_1AB\n")
        .unwrap();
    let pre = drain_until(&rx, &shell, "PRE_DONE_1AB", Duration::from_secs(20));
    assert!(
        !pre.contains(BODY),
        "extra share already mounted before add. captured: {pre:?}"
    );

    // 2. Add share, then read sentinel from inside the guest.
    sb.add_mount(Mount {
        name: "extra".into(),
        host_path: extra.clone(),
        guest_path: "/extra".into(),
        read_only: false,
        create_host_dir: false,
    })
    .expect("add_mount");
    sb.write_stdin(&shell, format!("cat /extra/{FNAME}; echo POST_ADD_2CD\n").as_bytes())
        .unwrap();
    let post = drain_until(&rx, &shell, "POST_ADD_2CD", Duration::from_secs(30));
    assert!(
        post.contains(BODY),
        "after add, sentinel not visible. captured: {post:?}"
    );

    // 3. Remove share. After this, /extra may be empty or fail to read.
    sb.remove_mount("extra").expect("remove_mount");
    sb.write_stdin(
        &shell,
        format!("cat /extra/{FNAME} 2>&1; echo POST_REM_3EF\n").as_bytes(),
    )
    .unwrap();
    let removed = drain_until(&rx, &shell, "POST_REM_3EF", Duration::from_secs(20));
    assert!(
        !removed.contains(BODY),
        "after remove, sentinel still readable. captured: {removed:?}"
    );

    sb.stop_vm().ok();
}
