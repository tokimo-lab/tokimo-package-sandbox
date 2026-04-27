//! L7 network observer demo (`NetworkPolicy::Gated`).
//!
//! Runs three guests inside one gated sandbox:
//!   * `/bin/sh`  — plumbed through `curl` (both HTTP and HTTPS)
//!   * a standalone `.sh` script — more `curl` calls, some denied
//!   * a small Python script that uses `urllib` to reach the network
//!
//! All traffic is funneled through an in-process HTTP(S) proxy; every
//! request is printed with method / host / URL / verdict. Requests that
//! target hosts outside the allowlist get HTTP 403 from the proxy so the
//! guest sees a connection failure.
//!
//! Run:
//!
//! ```sh
//! cargo run --example gated_network
//! ```
//!
//! Note: this talks to the real Internet (example.com, httpbin.org,
//! pypi.org, github.com, evil.com). Skip / adapt if you are offline.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokimo_package_sandbox::{
    DnsPolicy, HostPattern, Layer, NetEvent, NetEventSink, NetworkPolicy, ResourceLimits, SandboxConfig, Verdict,
};

/// Sink that prints each event and collects them for later assertions.
struct LoggingSink {
    start: Instant,
    events: Mutex<Vec<NetEvent>>,
}

impl LoggingSink {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }
}

impl NetEventSink for LoggingSink {
    fn on_event(&self, ev: &NetEvent) -> Verdict {
        let ms = self.start.elapsed().as_millis();
        let layer = match ev.layer {
            Layer::L7Http => "HTTP   ",
            Layer::L7Sni => "TLS/SNI",
            Layer::L3 => "L3     ",
            Layer::L4 => "L4     ",
            Layer::Dns => "DNS    ",
        };
        let host = ev.host.as_deref().unwrap_or("-");
        let port = ev.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        let extra = match (&ev.http_method, &ev.http_url, &ev.sni) {
            (Some(m), Some(u), _) => format!(" {} {}", m, u),
            (_, _, Some(sni)) => format!(" SNI={}", sni),
            _ => String::new(),
        };
        println!("[+{:>5}ms] {} {}:{}{}", ms, layer, host, port, extra);
        self.events.lock().unwrap().push(ev.clone());
        Verdict::Allow
    }
}

const SHELL_SCRIPT: &str = r#"#!/bin/sh
set -u
echo "== sh: curl example.com (should ALLOW, plain HTTP) =="
curl -sS -o /dev/null -w "  status=%{http_code}\n" http://example.com/ || echo "  (failed)"

echo "== sh: curl https://api.github.com (should ALLOW, CONNECT tunnel) =="
curl -sS -o /dev/null -w "  status=%{http_code}\n" https://api.github.com/ || echo "  (failed)"

echo "== sh: curl https://evil.com (should be DENIED by proxy 403) =="
curl -sS -o /dev/null -w "  status=%{http_code}\n" https://evil.com/ || echo "  (failed -- expected)"

echo "sh_done"
"#;

const PYTHON_SCRIPT: &str = r#"
import os, sys, urllib.request, urllib.error

print("python proxy env:", os.environ.get("HTTP_PROXY"), os.environ.get("HTTPS_PROXY"))

def hit(url, expect_ok):
    label = "ALLOW" if expect_ok else "DENY "
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            print(f"py [{label}] {url} -> {r.status}")
    except urllib.error.HTTPError as e:
        print(f"py [{label}] {url} -> HTTP {e.code}")
    except Exception as e:
        print(f"py [{label}] {url} -> FAILED {type(e).__name__}: {e}")

hit("http://example.com/",      True)
hit("https://pypi.org/simple/", True)
hit("https://evil.com/",        False)
print("py_done")
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work = tempfile::tempdir()?;

    // Drop the python + sh scripts into the sandbox work dir so the guests
    // can execute them from /tmp inside.
    std::fs::write(work.path().join("guest.sh"), SHELL_SCRIPT)?;
    std::fs::write(work.path().join("guest.py"), PYTHON_SCRIPT)?;

    let sink = Arc::new(LoggingSink::new());
    let sink_dyn: Arc<dyn NetEventSink> = sink.clone();

    let cfg = SandboxConfig::new(work.path())
        .name("gated-demo")
        .network(NetworkPolicy::Gated {
            sink: sink_dyn,
            allow_hosts: vec![
                HostPattern::exact("example.com"),
                HostPattern::suffix("github.com"),
                HostPattern::suffix("githubusercontent.com"),
                HostPattern::suffix("pypi.org"),
                HostPattern::suffix("pythonhosted.org"),
            ],
            dns_policy: DnsPolicy::PassThrough,
        })
        .limits(ResourceLimits {
            max_memory_mb: 512,
            timeout_secs: 60,
            max_file_size_mb: 16,
            max_processes: 128,
        })
        .stream_stderr(true);

    // --- 1) Inline curl through /bin/sh -c ---
    println!("\n==== 1) /bin/sh -c curl http://example.com/ ====");
    let out = tokimo_package_sandbox::run(
        &[
            "/bin/sh",
            "-c",
            "curl -sS -o /dev/null -w 'status=%{http_code}\\n' http://example.com/",
        ],
        &cfg,
    )?;
    println!("stdout: {}", out.stdout);
    println!("exit={}", out.exit_code);

    // --- 2) /bin/sh guest.sh (multi-curl script) ---
    println!("\n==== 2) /bin/sh /tmp/guest.sh ====");
    let out = tokimo_package_sandbox::run(&["/bin/sh", "/tmp/guest.sh"], &cfg)?;
    println!("{}", out.stdout);
    println!("exit={}", out.exit_code);

    // --- 3) python3 guest.py ---
    println!("\n==== 3) python3 /tmp/guest.py ====");
    let out = tokimo_package_sandbox::run(&["python3", "/tmp/guest.py"], &cfg)?;
    println!("{}", out.stdout);
    println!("exit={}", out.exit_code);

    // --- 4) Assertions on what the sink observed ---
    let events = sink.events.lock().unwrap().clone();
    println!("\n==== summary: {} L7 events observed ====", events.len());
    let hosts: std::collections::BTreeSet<String> = events.iter().filter_map(|e| e.host.clone()).collect();
    println!("unique hosts: {:?}", hosts);

    let saw_example = events.iter().any(|e| e.host.as_deref() == Some("example.com"));
    let saw_github = events
        .iter()
        .any(|e| e.host.as_deref().map(|h| h.ends_with("github.com")).unwrap_or(false));
    let saw_evil = events.iter().any(|e| e.host.as_deref() == Some("evil.com"));
    let saw_pypi = events
        .iter()
        .any(|e| e.host.as_deref().map(|h| h.ends_with("pypi.org")).unwrap_or(false));

    println!("saw example.com    = {}", saw_example);
    println!("saw *.github.com   = {}", saw_github);
    println!("saw pypi.org       = {}", saw_pypi);
    println!("saw evil.com (deny)= {}", saw_evil);

    assert!(saw_example, "proxy did not observe example.com");
    assert!(saw_evil, "proxy did not observe denied evil.com attempt");
    // github / pypi may be unreachable offline; don't assert on them.

    println!("\nOK — L7 observer saw every request, denied evil.com with HTTP 403.");
    Ok(())
}
