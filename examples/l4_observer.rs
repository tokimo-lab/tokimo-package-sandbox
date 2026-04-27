//! L4 network observer demo.
//!
//! Shows that `NetworkPolicy::Observed` / `Gated` catches raw TCP/UDP
//! `connect()` calls — traffic that bypasses the L7 HTTP(S) proxy. Examples
//! run inside the sandbox:
//!
//!   * `python3 -c "socket.socket().connect(('1.1.1.1', 53))"` — raw TCP,
//!     ignores HTTP_PROXY.
//!   * A shell loop with `/bin/sh` + `bash -c "exec 3<>/dev/tcp/..."` or
//!     `nc -z` — bash built-in TCP, again bypasses HTTP_PROXY.
//!   * A Python UDP send.
//!
//! Expected output on a kernel that supports seccomp-notify (no inherited
//! filter): L4 events for each `connect`/`sendto`. On hosts where
//! NEW_LISTENER is blocked (common on WSL2 and locked-down container
//! runtimes) the library falls back to L7-only observation and logs a
//! warning via `tracing`. The example detects that state and prints a
//! clear caveat.
//!
//! Run:
//!
//! ```sh
//! cargo run --example l4_observer
//! ```

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokimo_package_sandbox::{
    HostPattern, Layer, NetEvent, NetEventSink, NetworkPolicy, ResourceLimits, SandboxConfig, Verdict,
};

struct LoggingSink {
    start: Instant,
    events: Mutex<Vec<NetEvent>>,
}

impl NetEventSink for LoggingSink {
    fn on_event(&self, ev: &NetEvent) -> Verdict {
        let ms = self.start.elapsed().as_millis();
        let layer = match ev.layer {
            Layer::L7Http => "L7-HTTP",
            Layer::L7Sni => "L7-SNI ",
            Layer::L4 => "L4     ",
            Layer::L3 => "L3     ",
            Layer::Dns => "DNS    ",
        };
        let remote = ev
            .remote
            .map(|r| r.to_string())
            .or_else(|| ev.host.clone().zip(ev.port).map(|(h, p)| format!("{}:{}", h, p)))
            .unwrap_or_else(|| "-".into());
        let extra = match (&ev.http_method, &ev.http_url, &ev.sni) {
            (Some(m), Some(u), _) => format!(" {} {}", m, u),
            (_, _, Some(sni)) => format!(" SNI={}", sni),
            _ => String::new(),
        };
        let pid = ev.pid.map(|p| format!(" pid={}", p)).unwrap_or_default();
        let comm = ev.comm.as_deref().map(|c| format!(" comm={}", c)).unwrap_or_default();
        println!("[+{:>5}ms] {} {}{}{}{}", ms, layer, remote, pid, comm, extra);
        self.events.lock().unwrap().push(ev.clone());
        Verdict::Allow
    }
}

const PYTHON_RAW_TCP: &str = r#"
import socket, sys
targets = [("1.1.1.1", 53), ("8.8.8.8", 53)]
for host, port in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        print(f"py raw TCP -> {host}:{port} OK")
    except Exception as e:
        print(f"py raw TCP -> {host}:{port} FAILED {type(e).__name__}: {e}")
    finally:
        s.close()

# UDP sendto
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"\x00", ("1.1.1.1", 53))
    print("py raw UDP -> 1.1.1.1:53 sent")
except Exception as e:
    print(f"py raw UDP -> FAILED {e}")
"#;

const SHELL_RAW_TCP: &str = r#"#!/bin/bash
set -u
echo "== bash built-in TCP to 1.1.1.1:80 =="
if exec 3<>/dev/tcp/1.1.1.1/80; then
    echo "  connected (bash /dev/tcp)"
    exec 3<&- 3>&-
else
    echo "  failed"
fi

echo "== nc -z 1.1.1.1 80 =="
if command -v nc >/dev/null 2>&1; then
    nc -z -w 3 1.1.1.1 80 && echo "  OK" || echo "  fail"
else
    echo "  (nc not installed; skipping)"
fi

echo "== curl http://example.com/ (goes through HTTP_PROXY, L4 also sees connect to proxy) =="
curl -sS -o /dev/null -w "  status=%{http_code}\n" http://example.com/ || echo "  failed"
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable tracing so the L4-disabled warning (if any) is visible.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let work = tempfile::tempdir()?;
    std::fs::write(work.path().join("guest.py"), PYTHON_RAW_TCP)?;
    std::fs::write(work.path().join("guest.sh"), SHELL_RAW_TCP)?;

    let sink = Arc::new(LoggingSink {
        start: Instant::now(),
        events: Mutex::new(Vec::new()),
    });
    let sink_dyn: Arc<dyn NetEventSink> = sink.clone();

    let cfg = SandboxConfig::new(work.path())
        .name("l4-demo")
        .network(NetworkPolicy::Observed { sink: sink_dyn })
        .limits(ResourceLimits {
            max_memory_mb: 512,
            timeout_secs: 30,
            max_file_size_mb: 16,
            max_processes: 64,
        })
        .stream_stderr(true);

    println!("\n==== 1) python3 raw socket.connect + sendto ====");
    let out = tokimo_package_sandbox::run(&["python3", "/tmp/guest.py"], &cfg)?;
    println!("{}", out.stdout);
    println!("exit={}", out.exit_code);

    println!("\n==== 2) bash /dev/tcp + nc -z ====");
    let out = tokimo_package_sandbox::run(&["bash", "/tmp/guest.sh"], &cfg)?;
    println!("{}", out.stdout);
    println!("exit={}", out.exit_code);

    let events = sink.events.lock().unwrap().clone();
    let l4_count = events.iter().filter(|e| e.layer == Layer::L4).count();
    let l7_count = events.len() - l4_count;

    println!("\n==== summary ====");
    println!("total events: {}  (L4={}, L7={})", events.len(), l4_count, l7_count);

    if l4_count == 0 {
        println!(
            "\nNOTE: zero L4 events. This means the seccomp-notify backend \
            is disabled on this host (common on WSL2 and locked-down container \
            runtimes where an inherited seccomp filter blocks \
            SECCOMP_FILTER_FLAG_NEW_LISTENER). A warning was printed via \
            tracing at sandbox build time. Raw TCP / UDP traffic is therefore \
            invisible to the observer on this host. L7-aware tools (HTTP_PROXY \
            respecting) still work via the L7 proxy."
        );
    } else {
        println!("\nOK — L4 observer caught raw TCP / UDP traffic.");
    }

    // Keep a stable ordering of remotes for the human reader.
    let remotes: std::collections::BTreeSet<String> = events
        .iter()
        .filter(|e| e.layer == Layer::L4)
        .filter_map(|e| e.remote.map(|r| r.to_string()))
        .collect();
    if !remotes.is_empty() {
        println!("L4 remotes seen: {:?}", remotes);
    }

    // Silence unused-pattern-import warning on hosts without L4.
    let _ = HostPattern::exact("unused");
    Ok(())
}
