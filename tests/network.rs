mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until, host_has_ipv6, link_count};
use tokimo_package_sandbox::{NetworkPolicy, Sandbox};

// ---------------------------------------------------------------------------
// NetworkPolicy enforcement
// ---------------------------------------------------------------------------
//
// Blocked  → no NetworkAdapter device on the VM → guest has only `lo`.
// AllowAll → HCN NAT endpoint attached → guest gets at least one extra NIC.

#[test]
fn network_blocked_only_loopback() {
    let mut cfg = config("net-blocked");
    cfg.network = NetworkPolicy::Blocked;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let n = link_count(&rx, &sb, &shell);
    // Under the always-on netstack design (since macOS-NFS-mount), the
    // guest always has tk0 in its netns regardless of policy — Blocked
    // just gates egress at the smoltcp gateway. The only egress that
    // survives Blocked is registered LocalServices (e.g. NFS). So we
    // expect 2 links here: lo + tk0. The egress probe below proves
    // external traffic is still blocked.
    assert_eq!(n, 2, "Blocked policy must yield 2 links (lo + tk0), got {n}");

    // Egress probe MUST fail under Blocked.
    sb.write_stdin(
        &shell,
        b"timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo NET_LEAK_BLK || echo NET_DENIED_BLK'; echo NET_PROBE_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "NET_PROBE_DONE", Duration::from_secs(10));

    sb.stop_vm().ok();
    assert!(
        probe.contains("NET_DENIED_BLK"),
        "Blocked: egress should fail. probe={probe:?}"
    );
    assert!(
        !probe.contains("NET_LEAK_BLK"),
        "Blocked: TCP unexpectedly opened. probe={probe:?}"
    );
}

// Verifies that AllowAll attaches an HCN endpoint and the guest enumerates
// it as eth0 (synthetic Hyper-V NIC via `hv_netvsc`).
#[test]
fn network_allow_all_has_nic() {
    let mut cfg = config("net-allow");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let n = link_count(&rx, &sb, &shell);
    assert!(n >= 2, "AllowAll policy must yield ≥2 links (lo + NIC), got {n}");

    // Egress probe — AllowAll should let the guest open an outbound TCP
    // connection. We use 1.1.1.1:53 (Cloudflare DNS) as a stable target
    // that is reachable from virtually any internet-connected host.
    // The exact NIC IP / subnet depends on the backend (Windows: HCN NAT
    // 192.168.127.0/24; Linux bwrap: shared host netns; macOS VZ: bridged
    // NAT) — what we assert is the *capability*, not the implementation.
    sb.write_stdin(
        &shell,
        b"timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo NET_OK_ALLOW || echo NET_FAIL_ALLOW'; echo NET_PROBE_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "NET_PROBE_DONE", Duration::from_secs(15));

    sb.stop_vm().ok();
    assert!(
        probe.contains("NET_OK_ALLOW"),
        "AllowAll: egress to 1.1.1.1:53 should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// ICMPv4 PING — verify the userspace netstack proxies ping echo replies.
// Ignored by default: ICMP through smoltcp TAP is environment-sensitive
// (GitHub Actions runners may block raw ICMP). Run manually:
//   cargo test --test sandbox_integration network_allow_all_icmpv4_ping -- --ignored
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn network_allow_all_icmpv4_ping() {
    let mut cfg = config("net-ping4");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(
        &shell,
        b"timeout 8 ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1 && echo PING4_OK || echo PING4_FAIL; echo PING4_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "PING4_DONE", Duration::from_secs(15));
    sb.stop_vm().ok();
    assert!(
        probe.contains("PING4_OK"),
        "AllowAll: ICMPv4 ping to 1.1.1.1 should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// IPv6 TCP — verify the netstack carries v6 SYN/ACK to a real endpoint.
// ---------------------------------------------------------------------------
#[test]
fn network_allow_all_ipv6_tcp() {
    let mut cfg = config("net-tcp6");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Cloudflare v6 DNS over TCP.
    sb.write_stdin(
        &shell,
        b"timeout 8 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/53 && echo TCP6_OK || echo TCP6_FAIL'; echo TCP6_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "TCP6_DONE", Duration::from_secs(20));
    sb.stop_vm().ok();
    // Host must have IPv6 connectivity for this to pass; tolerate skip if
    // the host machine lacks v6 by allowing the host probe to confirm first.
    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping assertion (probe={probe:?})");
        return;
    }
    assert!(
        probe.contains("TCP6_OK"),
        "AllowAll: IPv6 TCP egress should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// ICMPv6 PING — verify the netstack proxies v6 echo replies.
// ---------------------------------------------------------------------------
#[test]
fn network_allow_all_icmpv6_ping() {
    let mut cfg = config("net-ping6");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    sb.write_stdin(
        &shell,
        b"timeout 8 ping -6 -c 1 -W 5 2606:4700:4700::1111 >/dev/null 2>&1 && echo PING6_OK || echo PING6_FAIL; echo PING6_DONE\n",
    )
    .unwrap();
    let probe = drain_until(&rx, &shell, "PING6_DONE", Duration::from_secs(15));
    sb.stop_vm().ok();
    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping assertion (probe={probe:?})");
        return;
    }
    assert!(
        probe.contains("PING6_OK"),
        "AllowAll: ICMPv6 ping should succeed. probe={probe:?}"
    );
}

// ---------------------------------------------------------------------------
// IPv6 DIAGNOSTIC — `cargo test ... network_allow_all_ipv6_diag -- --ignored --nocapture`
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn network_allow_all_ipv6_diag() {
    let mut cfg = config("net-v6-diag");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let cmds = b"echo === V6-ADDR ===\n\
	ip -6 addr\n\
	echo === V6-ROUTE ===\n\
	ip -6 route\n\
	echo === V6-NEIGH-BEFORE ===\n\
	ip -6 neigh\n\
	echo === DISABLE-IPV6 ===\n\
	cat /proc/sys/net/ipv6/conf/tk0/disable_ipv6 2>&1 || echo MISSING\n\
	echo === PING-V6-GW ===\n\
	timeout 3 ping -6 -c 2 -W 1 fd00:7f::1 2>&1 || echo PING_GW6_FAIL\n\
	echo === PING-V6-EXT ===\n\
	timeout 3 ping -6 -c 2 -W 1 2606:4700:4700::1111 2>&1 || echo PING_EXT6_FAIL\n\
	echo === V6-NEIGH-AFTER ===\n\
	ip -6 neigh\n\
	echo === TCP6 ===\n\
	timeout 5 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/53 && echo TCP6_OK || echo TCP6_FAIL'\n\
	echo V6_DIAG_DONE\n";
    sb.write_stdin(&shell, cmds).unwrap();
    let out = drain_until(&rx, &shell, "V6_DIAG_DONE", Duration::from_secs(30));
    sb.stop_vm().ok();
    eprintln!("=== V6 DIAG ===\n{out}\n=== END ===");
}

// ---------------------------------------------------------------------------
// DIAGNOSTIC — run with: cargo test --test sandbox_integration network_allow_all_diag -- --ignored --test-threads=1 --nocapture
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn network_allow_all_diag() {
    let mut cfg = config("net-diag");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let cmds = b"echo === LINKS ===\n\
	ip -s link\n\
	echo === ADDR ===\n\
	ip -4 addr\n\
	echo === ROUTE ===\n\
	ip -4 route\n\
	echo === NEIGH-BEFORE ===\n\
	ip neigh\n\
	echo === ARPING-GW ===\n\
	timeout 3 arping -c 2 -I eth0 192.168.127.1 2>&1 || echo arping_failed_or_missing\n\
	echo === PING-GW ===\n\
	timeout 3 ping -c 2 -W 1 192.168.127.1 2>&1 || echo ping_gw_failed\n\
	echo === PING-1.1.1.1 ===\n\
	timeout 3 ping -c 2 -W 1 1.1.1.1 2>&1 || echo ping_1111_failed\n\
	echo === NEIGH-AFTER ===\n\
	ip neigh\n\
	echo === TCP-SYN-PROBE ===\n\
	(timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo TCP_OK || echo TCP_FAIL') &\n\
	sleep 6\n\
	echo === LINKS-AFTER ===\n\
	ip -s link\n\
	echo DIAG_DONE\n";
    sb.write_stdin(&shell, cmds).unwrap();
    let out = drain_until(&rx, &shell, "DIAG_DONE", Duration::from_secs(30));
    sb.stop_vm().ok();
    eprintln!("=== GUEST DIAG OUTPUT ===\n{out}\n=== END ===");
}

// ---------------------------------------------------------------------------
// TCP RX PAYLOAD — verifies the netstack carries non-trivial response
// bytes back to the guest. The existing `network_allow_all_has_nic` only
// asserts SYN/ACK round-trip via `bash exec 3<>/dev/tcp/.../53` which sends
// & receives nothing. Real-world `curl http://...` exposes a separate bug:
// the upstream→guest direction was observed to RST mid-stream after a
// successful connect+send.
//
// This test runs HTTP/1.0 against `http://example.com` (small ~1.2KB body,
// stable, no TLS to confuse smoltcp) and asserts the response header
// contains `HTTP/1.0 200`.
// ---------------------------------------------------------------------------
#[test]
fn network_allow_all_tcp_recv_payload() {
    let mut cfg = config("net-rx");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    // Use raw bash /dev/tcp to avoid relying on curl in rootfs.
    // Send minimal HTTP/1.0 request, read response with `cat` until peer
    // closes (server signals EOF), then count bytes + check status line.
    let probe = b"timeout 15 bash -c '\
	exec 3<>/dev/tcp/93.184.216.34/80; \
	printf \"GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n\" >&3; \
	out=$(cat <&3); \
	echo BYTES=${#out}; \
	echo FIRSTLINE=$(printf %s \"$out\" | head -n1); \
	' && echo RX_DONE_OK || echo RX_DONE_FAIL\necho RX_PROBE_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    let out = drain_until(&rx, &shell, "RX_PROBE_END", Duration::from_secs(30));
    sb.stop_vm().ok();
    eprintln!("=== RX PROBE OUTPUT ===\n{out}\n=== END ===");
    assert!(
        out.contains("HTTP/1.0 200") || out.contains("HTTP/1.1 200"),
        "no HTTP 200 status line in response: {out:?}"
    );
    // example.com body is ~1.2KB; assert we got at least a few hundred bytes.
    assert!(
        out.lines().any(|l| {
            l.strip_prefix("BYTES=")
                .and_then(|n| n.trim().parse::<u64>().ok())
                .is_some_and(|n| n >= 500)
        }),
        "BYTES line missing or <500: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// IPv6 TCP RX PAYLOAD — the v4 sibling above (`tcp_recv_payload`)
// covers the v4 path; this one verifies the same upstream→guest data flow
// works over IPv6. Real-world repro: `curl http://www.baidu.com` from inside
// the VM resolved to IPv6, connected fine, sent the request, and then got
// `Empty reply from server` — the v6 path was RST'ing mid-response while
// v4 worked.
//
// Target: Cloudflare 1.1.1.1 over its IPv6 literal (2606:4700:4700::1111)
// on port 80. It's the same dual-stack endpoint we already use for
// `host_has_ipv6` and `network_allow_all_ipv6_tcp`; on port 80 it serves
// a stable 301-redirect page (~380 bytes) that proves real upstream→guest
// payload transfer.
// ---------------------------------------------------------------------------
#[test]
fn network_allow_all_tcp_recv_payload_ipv6() {
    let mut cfg = config("net-rx6");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping");
        return;
    }

    // Bash /dev/tcp/HOST/PORT accepts a numeric IPv6 literal (no brackets).
    let probe = b"timeout 15 bash -c '\
	exec 3<>/dev/tcp/2606:4700:4700::1111/80; \
	printf \"GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n\" >&3; \
	out=$(cat <&3); \
	echo BYTES=${#out}; \
	echo FIRSTLINE=$(printf %s \"$out\" | head -n1); \
	' && echo RX6_DONE_OK || echo RX6_DONE_FAIL\necho RX6_PROBE_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    let out = drain_until(&rx, &shell, "RX6_PROBE_END", Duration::from_secs(30));
    sb.stop_vm().ok();
    eprintln!("=== RX6 PROBE OUTPUT ===\n{out}\n=== END ===");
    assert!(
        out.contains("HTTP/1.0 ") || out.contains("HTTP/1.1 "),
        "no HTTP status line in IPv6 response: {out:?}"
    );
    // 1.1.1.1 :80 returns ~380 bytes (301 redirect page); assert ≥200.
    assert!(
        out.lines().any(|l| {
            l.strip_prefix("BYTES=")
                .and_then(|n| n.trim().parse::<u64>().ok())
                .is_some_and(|n| n >= 200)
        }),
        "BYTES line missing or <200 on IPv6 path: {out:?}"
    );
}

// Repeated IPv6 requests in sequence: `curl -6` against the same upstream a
// few times in a row used to hang after the first or second response. The
// regression repro is `for i in 1..=3 { GET / } | wait`. Each iteration
// must produce a real HTTP status line. Cloudflare 1.1.1.1:80 returns a
// 301 redirect page (~380 bytes) so we can assert N successful HTTP/1.x
// status lines.
#[test]
fn network_allow_all_tcp_recv_payload_ipv6_repeat() {
    let mut cfg = config("net-rx6-repeat");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping");
        return;
    }

    // Five sequential connections (new src port each) to the same v6 upstream.
    let probe = b"for i in 1 2 3 4 5; do \
	timeout 15 bash -c \"exec 3<>/dev/tcp/2606:4700:4700::1111/80; \
	printf 'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n' >&3; \
	out=\\$(cat <&3); \
	echo ITER=\\$i BYTES=\\${#out} FIRSTLINE=\\$(printf %s \\\"\\$out\\\" | head -n1)\"; \
	done; echo RX6R_PROBE_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    let out = drain_until(&rx, &shell, "RX6R_PROBE_END", Duration::from_secs(120));
    sb.stop_vm().ok();
    eprintln!("=== RX6 REPEAT OUTPUT ===\n{out}\n=== END ===");
    let success_iters = out
        .lines()
        .filter(|l| l.contains("HTTP/1.0 ") || l.contains("HTTP/1.1 "))
        .count();
    assert!(
        success_iters >= 5,
        "expected 5 HTTP status lines across iterations, got {success_iters}: {out:?}"
    );
}

// Multi-request hang reported by users running `curl -6 www.baidu.com`
// twice — the first request returns a response, the second hangs. The
// observable difference vs `tcp_recv_payload_ipv6_repeat` (which already
// passes) is that this exercises the DNS path: each curl invocation does
// a fresh getaddrinfo, which goes through the netstack as a UDP flow.
// We approximate that here without bundling curl by issuing two
// sequential `getent ahostsv6` lookups followed by a TCP fetch each.
#[test]
fn network_allow_all_dns_then_tcp_v6_repeat() {
    let mut cfg = config("net-dns-rx6-repeat");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping");
        return;
    }

    let probe = b"for i in 1 2 3; do \
	addr=$(getent ahostsv6 cloudflare.com 2>/dev/null | awk 'NR==1{print $1}'); \
	echo ITER=$i ADDR=$addr; \
	[ -z \"$addr\" ] && { echo ITER=$i NO_DNS; continue; }; \
	timeout 15 bash -c \"exec 3<>/dev/tcp/$addr/80; \
	printf 'GET / HTTP/1.0\\r\\nHost: cloudflare.com\\r\\n\\r\\n' >&3; \
	out=\\$(cat <&3); \
	echo ITER=$i BYTES=\\${#out} FIRSTLINE=\\$(printf %s \\\"\\$out\\\" | head -n1)\"; \
	done; echo DNSRX6_PROBE_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    let out = drain_until(&rx, &shell, "DNSRX6_PROBE_END", Duration::from_secs(120));
    sb.stop_vm().ok();
    eprintln!("=== DNS+RX6 REPEAT OUTPUT ===\n{out}\n=== END ===");
    let success_iters = out
        .lines()
        .filter(|l| l.contains("HTTP/1.0 ") || l.contains("HTTP/1.1 "))
        .count();
    assert!(
        success_iters >= 3,
        "expected 3 HTTP status lines across DNS+TCP iterations, got {success_iters}: {out:?}"
    );
}

// 10 sequential v6 requests with a 1 s pause between, mimicking the
// real-world repro of `curl -6 www.baidu.com` looping. Each iteration
// resolves the host (UDP DNS flow), opens a fresh TCP flow, sends GET,
// drains response, closes. The pause gives the netstack a chance to
// reap idle flows. The bug we are guarding against is the hvsock /
// shell-pty channel (or some downstream component) silently truncating
// output and then hanging the shell mid-stream after a handful of
// large bursts.
#[test]
fn network_allow_all_dns_then_tcp_v6_long_sequence() {
    let mut cfg = config("net-dns-rx6-long");
    cfg.network = NetworkPolicy::AllowAll;

    let sb = Sandbox::connect().expect("connect");
    sb.configure(cfg).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    if !host_has_ipv6() {
        eprintln!("host has no IPv6 connectivity, skipping");
        return;
    }

    let probe = b"for i in 1 2 3 4 5 6 7 8 9 10; do \
	addr=$(getent ahostsv6 cloudflare.com 2>/dev/null | awk 'NR==1{print $1}'); \
	[ -z \"$addr\" ] && { echo ITER=$i NO_DNS; sleep 1; continue; }; \
	timeout 15 bash -c \"exec 3<>/dev/tcp/$addr/80; \
	printf 'GET / HTTP/1.0\\r\\nHost: cloudflare.com\\r\\n\\r\\n' >&3; \
	out=\\$(cat <&3); \
	echo ITER=$i BYTES=\\${#out} FIRSTLINE=\\$(printf %s \\\"\\$out\\\" | head -n1)\"; \
	sleep 1; \
	done; echo LONGRX6_PROBE_END\n";
    sb.write_stdin(&shell, probe).unwrap();
    let out = drain_until(&rx, &shell, "LONGRX6_PROBE_END", Duration::from_secs(180));
    sb.stop_vm().ok();
    eprintln!("=== DNS+RX6 LONG OUTPUT ===\n{out}\n=== END ===");
    let success_iters = out
        .lines()
        .filter(|l| l.contains("HTTP/1.0 ") || l.contains("HTTP/1.1 "))
        .count();
    // We tolerate a few iters where DNS gave only v4 (Happy Eyeballs in
    // libc); but at least 8 of 10 must complete cleanly.
    assert!(
        success_iters >= 8,
        "expected >=8 HTTP status lines across 10 iterations, got {success_iters}: {out:?}"
    );
    // Crucially: the END marker must arrive — proves the shell didn't
    // hang mid-stream (which is the actual user-visible regression).
    assert!(
        out.contains("LONGRX6_PROBE_END"),
        "shell hung before reaching loop end marker: {out:?}"
    );
}
