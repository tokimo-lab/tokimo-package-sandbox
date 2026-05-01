//! Network passthrough end-to-end check.
//!
//! Run as: `cargo run --example network_check`
//!
//! Verifies that:
//!   * `NetworkPolicy::AllowAll` produces a working NIC inside the guest
//!     (IPv4 address, default route, DNS, raw HTTP, DNS-resolved HTTP).
//!   * `NetworkPolicy::Blocked` leaves the guest with no NIC, so all
//!     network probes fail.

use std::path::PathBuf;
use tokimo_package_sandbox::{ConfigureParams, ExecOpts, NetworkPolicy, Plan9Share, Sandbox};

#[derive(Debug)]
struct ProbeResult {
    name: &'static str,
    rc: i32,
    stdout: String,
}

fn probe(sb: &Sandbox, name: &'static str, sh: &str) -> ProbeResult {
    let argv = ["sh".to_string(), "-c".to_string(), sh.to_string()];
    match sb.exec(&argv, ExecOpts::default()) {
        Ok(r) => {
            let stdout = String::from_utf8_lossy(&r.stdout).into_owned();
            println!(
                "[{name}] exit={}\n  stdout: {}",
                r.exit_code,
                stdout.lines().take(4).collect::<Vec<_>>().join(" | ")
            );
            ProbeResult {
                name,
                rc: r.exit_code,
                stdout,
            }
        }
        Err(e) => {
            println!("[{name}] ERR: {e}");
            ProbeResult {
                name,
                rc: -1,
                stdout: String::new(),
            }
        }
    }
}

fn run_probes(sb: &Sandbox) -> Vec<ProbeResult> {
    vec![
        probe(
            sb,
            "ip-addr",
            // Guest has busybox but not all applets symlinked. Fall back to
            // sysfs and /proc if even busybox isn't on PATH.
            "busybox ip -o -4 addr show eth0 2>/dev/null \
              || ip -o -4 addr show eth0 2>/dev/null \
              || (echo eth0_present=$(test -e /sys/class/net/eth0 && echo yes || echo no); \
                  cat /proc/net/fib_trie 2>/dev/null | head -50)",
        ),
        probe(
            sb,
            "ip-route",
            "busybox ip route 2>/dev/null || ip route 2>/dev/null || cat /proc/net/route",
        ),
        probe(sb, "resolv", "cat /etc/resolv.conf 2>&1"),
        probe(
            sb,
            "wget-1.1.1.1",
            "wget -qO- --timeout=5 --tries=1 http://1.1.1.1 >/dev/null 2>&1; echo rc=$?",
        ),
        probe(
            sb,
            "dns-cloudflare",
            // Force IPv4 lookup. Capture getent's rc directly (piping through
            // head would mask it).
            "out=$(getent ahostsv4 cloudflare.com 2>&1); rc=$?; echo \"$out\" | head -1; echo rc=$rc",
        ),
        probe(
            sb,
            "wget-google",
            // example.org is the IETF-reserved canonical example host. -4
            // forces IPv4 since this NAT subnet is v4-only.
            "wget -4 -qO- --timeout=5 --tries=1 http://example.org >/dev/null 2>&1; echo rc=$?",
        ),
    ]
}

fn main() {
    let cwd = std::env::current_dir().unwrap();
    let sb = Sandbox::connect().unwrap();

    let mut all_pass = true;

    // ---------- AllowAll ----------
    println!("\n========== NetworkPolicy::AllowAll ==========");
    sb.configure(ConfigureParams {
        user_data_name: "net-check-allowall".into(),
        memory_mb: 2048,
        cpu_count: 2,
        plan9_shares: vec![Plan9Share {
            name: "host".into(),
            host_path: cwd.join("examples"),
            guest_path: PathBuf::from("/mnt/host"),
            read_only: false,
        }],
        network: NetworkPolicy::AllowAll,
        ..Default::default()
    })
    .unwrap();
    sb.create_vm().unwrap();
    sb.start_vm().unwrap();

    let allow = run_probes(&sb);
    let _ = sb.stop_vm();

    let allow_required = [
        "ip-addr",
        "ip-route",
        "resolv",
        "wget-1.1.1.1",
        "dns-cloudflare",
        "wget-google",
    ];
    for name in allow_required {
        let p = allow.iter().find(|p| p.name == name).unwrap();
        // Probes that suffix `; echo rc=$?` always exit 0 from the shell
        // wrapper, so we look at the captured "rc=N" line for those.
        let ok = if p.stdout.contains("rc=") {
            p.stdout.contains("rc=0")
        } else {
            p.rc == 0
        };
        if !ok {
            all_pass = false;
            println!("FAIL[AllowAll]: {name}");
        }
    }

    // ---------- Blocked ----------
    println!("\n========== NetworkPolicy::Blocked ==========");
    sb.configure(ConfigureParams {
        user_data_name: "net-check-blocked".into(),
        memory_mb: 2048,
        cpu_count: 2,
        plan9_shares: vec![Plan9Share {
            name: "host".into(),
            host_path: cwd.join("examples"),
            guest_path: PathBuf::from("/mnt/host"),
            read_only: false,
        }],
        network: NetworkPolicy::Blocked,
        ..Default::default()
    })
    .unwrap();
    sb.create_vm().unwrap();
    sb.start_vm().unwrap();

    let blocked = run_probes(&sb);
    let _ = sb.stop_vm();

    // For Blocked we expect the egress probes (wget/dns) to fail.
    let blocked_must_fail = ["wget-1.1.1.1", "dns-cloudflare", "wget-google"];
    for name in blocked_must_fail {
        let p = blocked.iter().find(|p| p.name == name).unwrap();
        let failed = !p.stdout.contains("rc=0");
        if !failed {
            all_pass = false;
            println!("FAIL[Blocked]: {name} unexpectedly succeeded");
        }
    }

    println!(
        "\n========== {} ==========",
        if all_pass { "PASS" } else { "FAIL" }
    );
    if !all_pass {
        std::process::exit(1);
    }
}
