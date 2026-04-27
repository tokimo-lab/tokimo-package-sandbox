//! Smoke test for the PID-1 docker-shim sandbox init.
//!
//! Spawns a long-lived bwrap container whose PID 1 is `tokimo-sandbox-init`,
//! connects to its SOCK_SEQPACKET control socket, performs a `Hello`
//! handshake, asserts `init_pid == 1`, then issues `Shutdown`.
//!
//!     cargo run --example init_smoke
//!
//! Linux only.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use tokimo_package_sandbox::{InitClient, NetworkPolicy, SandboxConfig};

    let work = std::env::temp_dir().join("tps-init-smoke");
    std::fs::create_dir_all(&work)?;

    let cfg = SandboxConfig::new(&work).network(NetworkPolicy::Blocked);

    eprintln!("[smoke] spawn_init …");
    let mut spawned = tokimo_package_sandbox::spawn_init(&cfg)?;
    let host_sock = spawned.host_control_dir.path().join("control.sock");
    eprintln!("[smoke] bwrap pid={}, sock={}", spawned.child.id(), host_sock.display());

    // Wait up to 5s for init to bind the socket inside the sandbox; the bind
    // mount makes it appear at host_sock on our side.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !host_sock.exists() {
        if Instant::now() > deadline {
            // Drain bwrap stderr so we know why init didn't come up.
            if let Some(stderr) = spawned.child.stderr.take() {
                let mut s = String::new();
                use std::io::Read;
                let _ = std::io::BufReader::new(stderr).read_to_string(&mut s);
                eprintln!("[smoke] bwrap stderr:\n{s}");
            }
            return Err(format!("control socket never appeared at {}", host_sock.display()).into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    eprintln!("[smoke] connect …");
    let client = InitClient::connect(&host_sock)?;

    eprintln!("[smoke] hello …");
    let info = match client.hello() {
        Ok(v) => v,
        Err(e) => {
            // Drain bwrap stderr for diagnostics.
            if let Some(stderr) = spawned.child.stderr.take() {
                let mut s = String::new();
                use std::io::Read;
                let _ = std::io::BufReader::new(stderr).read_to_string(&mut s);
                eprintln!("[smoke] bwrap stderr (post-fail):\n{s}");
            }
            let _ = spawned.child.kill();
            return Err(e.into());
        }
    };
    eprintln!("[smoke] init says: init_pid={info}");
    assert_eq!(info, 1, "init_pid must be 1 inside the sandbox");

    eprintln!("[smoke] shutdown …");
    client.shutdown()?;

    let status = spawned.child.wait()?;
    eprintln!("[smoke] bwrap exit: {status}");

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("init_smoke is Linux-only");
}
