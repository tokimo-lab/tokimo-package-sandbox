//! Smoke test for `Session::open_pty` (Linux only).
//!
//! Spawns a sandboxed bash with a controlling terminal, writes
//! `echo hello\nexit\n`, reads PTY master output, and asserts we see "hello".

#[cfg(target_os = "linux")]
fn main() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::time::Duration;
    use tokimo_package_sandbox::{SandboxConfig, Session};

    let tmp = tempfile::tempdir().expect("tmpdir");
    let cfg = SandboxConfig::new(tmp.path());
    let sess = Session::open(&cfg).expect("open session");

    let argv: Vec<String> = ["/bin/bash", "--noprofile", "--norc"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut pty = sess.open_pty(24, 80, &argv, &[], None).expect("open_pty");

    // Take ownership of the master fd so we can read/write directly.
    let master = pty.take_master().expect("master fd");
    // Make a File from the OwnedFd for blocking I/O.
    let raw = master.as_raw_fd();
    // Set a generous nonblock + read-with-timeout via select isn't worth
    // it for a smoke test — use blocking File and rely on bash exiting.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    std::mem::forget(master); // ownership transferred into File above
    use std::os::fd::FromRawFd;

    // Write commands.
    file.write_all(b"echo HELLO_FROM_PTY\n").expect("write");
    file.write_all(b"exit\n").expect("write exit");
    file.flush().ok();

    // Wait for child exit.
    let rc = pty.wait(Duration::from_secs(5));
    println!("[pty_smoke] child exit rc = {:?}", rc);

    // Drain remaining bytes.
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    let s = String::from_utf8_lossy(&buf);
    println!("[pty_smoke] output ({} bytes):\n{}", buf.len(), s);
    assert!(
        s.contains("HELLO_FROM_PTY"),
        "expected HELLO_FROM_PTY in PTY output, got:\n{s}"
    );

    drop(file);
    drop(pty);
    sess.close().ok();
    println!("[pty_smoke] OK");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("pty_smoke is Linux-only");
}
