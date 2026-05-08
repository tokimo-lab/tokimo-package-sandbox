#![cfg(target_os = "linux")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::{HostExecAction, HostExecCtx, Sandbox};

#[test]
fn host_exec_register_and_callback_invoked() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec1")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    // Record received contexts.
    let received: Arc<Mutex<Vec<HostExecCtx>>> = Arc::new(Mutex::new(Vec::new()));
    let received_cl = received.clone();
    sb.on_host_exec(Arc::new(move |ctx: HostExecCtx| {
        received_cl.lock().unwrap().push(ctx.clone());
        // Echo back via stdout via a tiny `printf` on the host.
        HostExecAction::RunOnHost {
            argv: vec!["printf".into(), "BRIDGED:%s".into(), ctx.command.clone()],
            env: ctx.env,
            cwd: ctx.cwd,
        }
    }))
    .expect("on_host_exec");

    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    sb.add_host_command("mycmd").expect("add_host_command");

    let cmds = sb.list_host_commands().expect("list");
    assert!(cmds.contains(&"mycmd".to_string()), "list returned: {cmds:?}");

    const END: &str = "END_HOSTEXEC_1";
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, b"mycmd\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(
        captured.contains("BRIDGED:mycmd"),
        "expected BRIDGED:mycmd in: {captured:?}"
    );
    let got = received.lock().unwrap();
    assert!(!got.is_empty(), "callback was not invoked");
    assert_eq!(got[0].command, "mycmd");
}

#[test]
fn host_exec_remove_and_set() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec2")).expect("configure");
    sb.on_host_exec(Arc::new(|_ctx: HostExecCtx| HostExecAction::Reject {
        exit_code: 0,
        message: None,
    }))
    .expect("on_host_exec");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    sb.add_host_command("a").unwrap();
    sb.add_host_command("b").unwrap();
    let mut cmds = sb.list_host_commands().unwrap();
    cmds.sort();
    assert_eq!(cmds, vec!["a".to_string(), "b".to_string()]);

    sb.remove_host_command("a").unwrap();
    let cmds = sb.list_host_commands().unwrap();
    assert_eq!(cmds, vec!["b".to_string()]);

    sb.set_host_commands(&["x".into(), "y".into(), "z".into()]).unwrap();
    let mut cmds = sb.list_host_commands().unwrap();
    cmds.sort();
    assert_eq!(cmds, vec!["x".to_string(), "y".to_string(), "z".to_string()]);

    sb.stop_vm().ok();
}
