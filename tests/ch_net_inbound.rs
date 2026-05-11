//! Integration test: inbound port forwarding via passt -t.
//!
//! Spawns a real cloud-hypervisor microVM with passt networking enabled, starts
//! a guest HTTP server on port 8080, and fetches `/passwd` through a forwarded
//! host port.  Prints boot / agent-ready / forward-curl timings.
//!
//! # Prerequisites
//!
//! - Linux host with readable/writable `/dev/kvm`
//! - Built cloud-hypervisor kernel/initrd assets (`make ch-vmlinux` and `make ch-initrd`)
//! - Built passt binary (`make passt`)
//!
//! # Running
//!
//! ```bash
//! cd packages/tokimo-package-sandbox
//! cargo test --test ch_net_inbound -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::net::TcpListener;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::ch::rpc::{GuestRpc, Response};
use tokimo_package_sandbox::ch::vmm::{
    ChVm, ChVmConfig, NetworkConfig, PortForward, PortProto, ch_initrd_path, ch_vmlinux_path, locate_project_root,
    next_cid,
};
use tokimo_package_sandbox::ch_probe::probe_ch;

/// Returns a skip reason string if the host cannot run CH VMs with passt networking.
fn skip_reason() -> Option<String> {
    if let Err(e) = OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        return Some(format!(
            "/dev/kvm cannot be opened with read/write access: {} — \
             ensure current user is in the 'kvm' group and has proper permissions",
            e
        ));
    }

    let probe = probe_ch();
    if !probe.is_ready() {
        return Some(format!("host not ready for cloud-hypervisor:\n{}", probe.report()));
    }
    match ch_initrd_path() {
        Err(e) => return Some(format!("ch_initrd_path error: {e}")),
        Ok(p) if !p.exists() => {
            return Some(format!("initrd not found at '{}' — run: make ch-initrd", p.display()));
        }
        Ok(_) => {}
    }
    match ch_vmlinux_path() {
        Err(e) => return Some(format!("ch_vmlinux_path error: {e}")),
        Ok(p) if !p.exists() => {
            return Some(format!("vmlinux not found at '{}' — run: make ch-vmlinux", p.display()));
        }
        Ok(_) => {}
    }

    let passt_binary = passt_path();
    if !passt_binary.exists() {
        return Some(format!(
            "passt binary not found at '{}' — run: make passt",
            passt_binary.display()
        ));
    }

    None
}

fn passt_path() -> PathBuf {
    let root = locate_project_root().expect("cannot locate project root");
    root.join("bin/passt/current/bin/passt")
}

/// Polls the guest agent until it responds to ping.  Returns elapsed duration.
fn wait_for_guest_agent(rt: &tokio::runtime::Runtime, rpc: &GuestRpc) -> Duration {
    let start = Instant::now();
    let result = rt.block_on(async {
        let timeout = Duration::from_secs(30);
        loop {
            match rpc.ping().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if start.elapsed() >= timeout {
                        return Err(format!(
                            "guest-agent did not respond within {:.0}s: {e}",
                            timeout.as_secs_f32()
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });
    result.expect("guest-agent ready");
    start.elapsed()
}

fn free_host_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral host port");
    listener.local_addr().expect("ephemeral host port addr").port()
}

fn collect_command_result(command_name: &str, frames: Vec<Response>) -> (Option<i32>, Option<String>) {
    let mut exit_code = None;
    let mut stderr = String::new();

    for frame in frames {
        match frame {
            Response::Stderr { data } => stderr.push_str(&data),
            Response::Exit { code } => exit_code = Some(code),
            Response::Error { msg } => panic!("{command_name}: guest error: {msg}"),
            Response::Pong | Response::Stdout { .. } | Response::MountStatus { .. } => {}
        }
    }

    let stderr = if stderr.is_empty() { None } else { Some(stderr) };
    (exit_code, stderr)
}

/// Fetches `http://127.0.0.1:{host_port}/passwd` until a 200 response with a
/// non-empty body arrives.  Returns the elapsed duration of the successful
/// request.
fn fetch_passwd(host_port: u16) -> Duration {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let url = format!("http://127.0.0.1:{host_port}/passwd");
    let poll_deadline = Duration::from_secs(20);
    let poll_start = Instant::now();
    let mut last_error: Option<String> = None;

    loop {
        if poll_start.elapsed() >= poll_deadline {
            let last_error = last_error.as_deref().unwrap_or("no request attempted");
            panic!("guest HTTP server did not respond via forwarded port {host_port}: {last_error}");
        }

        let req_start = Instant::now();
        match client.get(&url).send() {
            Ok(response) => {
                let status = response.status();
                let elapsed = req_start.elapsed();
                match response.text() {
                    Ok(body) if status.is_success() && !body.is_empty() => return elapsed,
                    Ok(body) => {
                        last_error = Some(format!("unexpected response status={status} body={body:?}"));
                    }
                    Err(e) => {
                        last_error = Some(format!("failed to read response text after status {status}: {e}"));
                    }
                }
            }
            Err(e) => {
                last_error = Some(e.to_string());
            }
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Test passt inbound forwarding: host connects to a forwarded port backed by a
/// guest HTTP server serving `/etc`.  Tries `busybox httpd -f -p 8080 -h /etc`
/// first; falls back to a raw nc loop so `/passwd` still returns a non-empty
/// body even when httpd is unavailable.
///
/// The test is `#[ignore]` because it requires KVM hardware access, a built
/// initrd, cloud-hypervisor, and passt binaries — not available in standard CI.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires KVM + cloud-hypervisor + passt + initrd (make ch-initrd)"]
fn ch_net_inbound_tcp_forward() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let probe = probe_ch();
    let ch_binary = probe.ch_binary.expect("is_ready guarantees ch_binary");
    let cid = next_cid();
    let passt_binary = passt_path();
    let host_port = free_host_port();

    let vm_config = ChVmConfig {
        cid,
        ch_binary,
        kernel: ch_vmlinux_path().expect("vmlinux path"),
        initrd: ch_initrd_path().expect("initrd path"),
        memory_mb: 256,
        cpu_count: 1,
        shared_dir: None,
        network: Some(NetworkConfig {
            passt_binary,
            mac_addr: None,
            port_forwards: vec![PortForward {
                proto: PortProto::Tcp,
                host_port,
                guest_port: 8080,
                host_addr: Some("127.0.0.1".to_string()),
            }],
        }),
    };

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    // ── boot timing ──────────────────────────────────────────────────────────
    let t_boot_start = Instant::now();
    let mut vm = rt.block_on(ChVm::spawn(vm_config)).expect("VM spawn");
    let t_boot = t_boot_start.elapsed();

    let test_result = catch_unwind(AssertUnwindSafe(|| {
        // ── agent-ready timing ───────────────────────────────────────────────
        let rpc = GuestRpc::new(vm.vsock_socket.clone(), 1024);
        let t_agent = wait_for_guest_agent(&rt, &rpc);

        // ── spawn httpd with nc fallback as a single background command ──────
        //
        // Start `busybox httpd -f` in the background, sleep briefly, then
        // probe http://127.0.0.1:8080/passwd from inside the guest with wget.
        // If the probe succeeds (200 + non-empty body), keep httpd alive via
        // `wait`.  If it fails (404, wget missing, or any error), kill httpd
        // and fall back to a raw nc loop that always returns HTTP 200 "hello".
        let rpc2 = GuestRpc::new(vm.vsock_socket.clone(), 1024);
        let server_argv: Vec<String> = vec![
            "sh".into(),
            "-c".into(),
            concat!(
                "busybox httpd -f -p 8080 -h /etc &\n",
                "HTTPD_PID=$!\n",
                "sleep 1\n",
                "if busybox wget -q -O /dev/null http://127.0.0.1:8080/passwd 2>/dev/null; then\n",
                "  wait $HTTPD_PID\n",
                "else\n",
                "  kill $HTTPD_PID 2>/dev/null\n",
                "  while true; do ",
                "printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 5\\r\\n\\r\\nhello' | busybox nc -l -p 8080; ",
                "done\n",
                "fi"
            )
            .into(),
        ];
        std::thread::spawn(move || {
            let rt2 = tokio::runtime::Runtime::new().expect("tokio runtime for guest server");
            match rt2.block_on(rpc2.spawn_command(&server_argv)) {
                Ok(frames) => {
                    let (exit_code, stderr) = collect_command_result("guest HTTP server", frames);
                    if exit_code != Some(0) {
                        eprintln!("guest HTTP server exited with {exit_code:?}; stderr={stderr:?}");
                    }
                }
                Err(e) => eprintln!("guest HTTP server spawn failed: {e}"),
            }
        });

        // Give the server time to bind before the first request.
        std::thread::sleep(Duration::from_millis(200));

        // ── forward-curl timing ──────────────────────────────────────────────
        let t_forward_curl = fetch_passwd(host_port);

        eprintln!(
            "timings: boot_ms={} agent_ms={} forward_curl_ms={} host_port={}",
            t_boot.as_millis(),
            t_agent.as_millis(),
            t_forward_curl.as_millis(),
            host_port,
        );
    }));

    let shutdown_result = rt.block_on(vm.shutdown(Duration::from_secs(2)));
    if let Err(payload) = test_result {
        let _ = shutdown_result;
        resume_unwind(payload);
    }
    shutdown_result.expect("VM shutdown");
}
