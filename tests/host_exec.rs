//! Integration tests for the Host-Exec Bridge.
//!
//! These tests run on all supported platforms (Linux bwrap, macOS VZ, Windows
//! HCS). On platforms whose backend has not yet shipped host-exec support, the
//! test gracefully skips rather than failing.

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

    let received: Arc<Mutex<Vec<HostExecCtx>>> = Arc::new(Mutex::new(Vec::new()));
    let received_cl = received.clone();
    let cb = Arc::new(move |ctx: HostExecCtx| {
        received_cl.lock().unwrap().push(ctx.clone());
        HostExecAction::RunOnHost {
            argv: vec!["printf".into(), "BRIDGED:%s".into(), ctx.command.clone()],
            env: ctx.env,
            cwd: ctx.cwd,
        }
    });

    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
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

// ── test 2 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_remove_and_set() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec2")).expect("configure");
    let reject_cb = Arc::new(|_ctx: HostExecCtx| HostExecAction::Reject {
        exit_code: 0,
        message: None,
    });
    if sb.on_host_exec(reject_cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
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

// ── test 3 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_reject_returns_nonzero_exit() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec3")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    let cb = Arc::new(|_ctx: HostExecCtx| HostExecAction::Reject {
        exit_code: 42,
        message: None,
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.add_host_command("rejectcmd").unwrap();

    const END: &str = "END_REJECT";
    let shell = sb.shell_id().expect("shell_id");
    // Run command; capture its exit code into $RC, then echo sentinel.
    sb.write_stdin(&shell, b"rejectcmd; echo RC=$?\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(captured.contains("RC=42"), "expected RC=42 in: {captured:?}");
}

// ── test 4 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_callback_receives_env() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec4")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    let captured_env: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let env_clone = captured_env.clone();
    let cb = Arc::new(move |ctx: HostExecCtx| {
        *env_clone.lock().unwrap() = ctx.env.clone();
        HostExecAction::RunOnHost {
            argv: vec!["true".into()],
            env: ctx.env,
            cwd: ctx.cwd,
        }
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.add_host_command("envcmd").unwrap();

    const END: &str = "END_ENV";
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, b"MY_SENTINEL=hello envcmd\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    let env = captured_env.lock().unwrap();
    let has_sentinel = env.iter().any(|(k, v)| k == "MY_SENTINEL" && v == "hello");
    assert!(has_sentinel, "MY_SENTINEL=hello not found in forwarded env: {env:?}");
}

// ── test 5 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_callback_receives_cwd() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec5")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    let captured_cwd: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cwd_clone = captured_cwd.clone();
    let cb = Arc::new(move |ctx: HostExecCtx| {
        *cwd_clone.lock().unwrap() = ctx.cwd.clone();
        HostExecAction::RunOnHost {
            argv: vec!["true".into()],
            env: ctx.env,
            cwd: ctx.cwd,
        }
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.add_host_command("cwdcmd").unwrap();

    const END: &str = "END_CWD";
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, b"cd /tmp && cwdcmd\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    let cwd = captured_cwd.lock().unwrap().clone();
    assert_eq!(cwd.as_deref(), Some("/tmp"), "expected cwd=/tmp, got {cwd:?}");
}

// ── test 6 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_unregistered_command_not_found_in_bridge_dir() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec6")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    // We need the bridge to exist so the PATH is set up, but we don't register "ghostcmd".
    let cb = Arc::new(|_: HostExecCtx| HostExecAction::Reject {
        exit_code: 0,
        message: None,
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    // Register one unrelated command so the bridge dir is initialised.
    sb.add_host_command("other").unwrap();

    const END: &str = "END_NOTFOUND";
    let shell = sb.shell_id().expect("shell_id");
    // ghostcmd should NOT be found (it's not in PATH via bridge dir).
    sb.write_stdin(&shell, b"type ghostcmd 2>/dev/null && echo FOUND || echo NOTFOUND\n")
        .unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(captured.contains("NOTFOUND"), "expected NOTFOUND in: {captured:?}");
}

// ── test 7 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_list_empty_before_any_add() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec7")).expect("configure");
    let cb = Arc::new(|_: HostExecCtx| HostExecAction::Reject {
        exit_code: 0,
        message: None,
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    let cmds = sb.list_host_commands().unwrap();
    assert!(cmds.is_empty(), "expected empty list at start, got {cmds:?}");

    sb.stop_vm().ok();
}

// ── test 8 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_set_replaces_all_commands() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec8")).expect("configure");
    let cb = Arc::new(|_: HostExecCtx| HostExecAction::Reject {
        exit_code: 0,
        message: None,
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    sb.add_host_command("old1").unwrap();
    sb.add_host_command("old2").unwrap();

    sb.set_host_commands(&["new1".into(), "new2".into()]).unwrap();
    let mut cmds = sb.list_host_commands().unwrap();
    cmds.sort();
    assert_eq!(cmds, vec!["new1".to_string(), "new2".to_string()]);

    sb.stop_vm().ok();
}

// ── test 9 ───────────────────────────────────────────────────────────────────

#[test]
fn host_exec_callback_updated_after_start_vm() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec9")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    // Register a first callback that rejects everything.
    let cb_initial = Arc::new(|_: HostExecCtx| HostExecAction::Reject {
        exit_code: 99,
        message: None,
    });
    if sb.on_host_exec(cb_initial).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.add_host_command("updatecmd").unwrap();

    // Replace with a callback that prints a known string.
    let cb_new = Arc::new(|ctx: HostExecCtx| HostExecAction::RunOnHost {
        argv: vec!["printf".into(), "UPDATED\n".into()],
        env: ctx.env,
        cwd: ctx.cwd,
    });
    sb.on_host_exec(cb_new).expect("on_host_exec after start_vm");

    const END: &str = "END_UPDATE";
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, b"updatecmd\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(captured.contains("UPDATED"), "expected UPDATED in: {captured:?}");
}

// ── test 10 ──────────────────────────────────────────────────────────────────

#[test]
fn host_exec_remove_all_leaves_empty_list() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec10")).expect("configure");
    let cb = Arc::new(|_: HostExecCtx| HostExecAction::Reject {
        exit_code: 0,
        message: None,
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());

    sb.add_host_command("alpha").unwrap();
    sb.add_host_command("beta").unwrap();
    sb.remove_host_command("alpha").unwrap();
    sb.remove_host_command("beta").unwrap();

    let cmds = sb.list_host_commands().unwrap();
    assert!(cmds.is_empty(), "expected empty list after removing all, got {cmds:?}");

    sb.stop_vm().ok();
}

// ── test 11 ──────────────────────────────────────────────────────────────────

#[test]
fn host_exec_stdout_piped_back_to_guest() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec11")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    let cb = Arc::new(|ctx: HostExecCtx| HostExecAction::RunOnHost {
        argv: vec!["printf".into(), "STDOUT_TOKEN\n".into()],
        env: ctx.env,
        cwd: ctx.cwd,
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.add_host_command("printcmd").unwrap();

    const END: &str = "END_STDOUT";
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, b"printcmd\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(
        captured.contains("STDOUT_TOKEN"),
        "expected STDOUT_TOKEN in: {captured:?}"
    );
}

// ── test 12 ──────────────────────────────────────────────────────────────────

#[test]
fn host_exec_multiple_invocations_of_same_command() {
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config("hostexec12")).expect("configure");
    let rx = sb.subscribe().expect("subscribe");

    let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count_cl = count.clone();
    let cb = Arc::new(move |ctx: HostExecCtx| {
        let n = count_cl.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        HostExecAction::RunOnHost {
            argv: vec!["printf".into(), format!("CALL{n}\n")],
            env: ctx.env,
            cwd: ctx.cwd,
        }
    });
    if sb.on_host_exec(cb).is_err() {
        eprintln!("SKIP: host-exec not supported on this backend");
        return;
    }
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    sb.add_host_command("multicmd").unwrap();

    const END: &str = "END_MULTI";
    let shell = sb.shell_id().expect("shell_id");
    sb.write_stdin(&shell, b"multicmd && multicmd && multicmd\n").unwrap();
    sb.write_stdin(&shell, format!("echo {END}\n").as_bytes()).unwrap();

    let captured = drain_until(&rx, &shell, END, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(captured.contains("CALL1"), "expected CALL1 in: {captured:?}");
    assert!(captured.contains("CALL2"), "expected CALL2 in: {captured:?}");
    assert!(captured.contains("CALL3"), "expected CALL3 in: {captured:?}");
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 3);
}
