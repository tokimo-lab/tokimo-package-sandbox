mod common;

#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use common::{SandboxGuard, config, drain_until, workspace_dir};
#[cfg(target_os = "macos")]
use tokimo_package_sandbox::{Mount, Sandbox};

#[test]
#[cfg(target_os = "macos")]
fn nfs_dynamic_mount_writes_to_host() {
    const SENTINEL: &str = "NFS_DYN_WROTE_F19C";

    let label = "nfs-dyn";
    let host = workspace_dir(&format!("{label}-share"));
    let _ = std::fs::remove_file(host.join("hello.txt"));

    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    sb.add_mount(Mount {
        name: "share1".into(),
        host_path: host.clone(),
        guest_path: "/mnt/share1".into(),
        read_only: false,
        create_host_dir: true,
    })
    .expect("add_mount");

    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(
        &shell,
        format!("echo {SENTINEL} > /mnt/share1/hello.txt; echo NFS_DONE_4F8\n").as_bytes(),
    )
    .unwrap();
    let _ = drain_until(&rx, &shell, "NFS_DONE_4F8", Duration::from_secs(30));

    let read = std::fs::read_to_string(host.join("hello.txt")).unwrap_or_default();
    assert!(
        read.contains(SENTINEL),
        "host did not see guest write through NFS mount: got {read:?}"
    );

    sb.remove_mount("share1").ok();
    sb.stop_vm().ok();
}
