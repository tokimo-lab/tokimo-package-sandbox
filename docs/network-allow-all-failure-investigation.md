# `network_allow_all_has_nic` failure on Windows — open investigation

> **Status: UNRESOLVED. All findings below are observations + working
> hypotheses, NOT a verified root cause. The PTY work in
> [PROTOCOL_VERSION 4](../plan/pty-api-cross-platform.md) was committed
> with this test failing because the failure path does not touch any
> code modified by the PTY work — see "Scope check" below.**

## What was observed

On the Windows test runner, after rebuilding from the PTY branch and
re-deploying the rebaked initrd, the integration suite reports:

```
test result: FAILED. 19 passed; 1 failed; 0 ignored; 0 measured
failures: network_allow_all_has_nic
panic: AllowAll: egress to 1.1.1.1:53 should succeed. probe="NET_PROBE_DONE\n"
```

The probe text being just `"NET_PROBE_DONE\n"` means neither the
`NET_OK_ALLOW` nor the `NET_FAIL_ALLOW` branch printed — the bash
subshell `exec 3<>/dev/tcp/1.1.1.1/53` hung past the `timeout 5` and was
SIGTERM'd before reaching either branch. This is the symptom of an
outbound TCP SYN never receiving a SYN-ACK.

## What was checked (in the running guest)

A diagnostic example (`examples/net_diag.rs`, since removed) was used to
shell into a `NetworkPolicy::AllowAll` session and inspect state. From
inside the guest:

| Check | Result |
|---|---|
| `cat /proc/net/dev` | `eth0` and `lo` both listed |
| `busybox ip link` | `eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500` |
| `busybox ip addr` | `inet 192.168.127.2/24 scope global eth0` |
| `busybox route -n` | `default via 192.168.127.1`, `192.168.127.0/24 dev eth0` |
| `cat /proc/net/route` | gateway 192.168.127.1 in routing table |
| `busybox ifconfig eth0` | `UP BROADCAST RUNNING MULTICAST` |
| TX packets after probe | only `1` (the gratuitous ARP) — no SYN visible |

So inside the guest the configuration looks textbook for an HCN NAT
endpoint with the static-IP scheme baked into `packaging/vm-image/init.sh`.
No mismatch with what the host sent in the HCN endpoint config
(`C:\tokimo-debug\last-hcn-endpoint.json`).

> **Caveat:** `cat /proc/net/snmp` and `tcpdump`-style traces were not
> captured. We do not have direct evidence that the SYN was actually
> emitted onto the synthetic NIC vs. dropped by the kernel.

## What was checked (on the Windows host)

| Check | Result |
|---|---|
| `Test-NetConnection 1.1.1.1 -Port 53` from host | TRUE (host has working egress) |
| `Get-NetAdapter` for `vEthernet (tokimo-sandbox-nat)` | Up |
| `Get-NetIPInterface` IPv4 forwarding on that adapter | Enabled |
| `hnsdiag list networks` | The HCN NAT network exists with subnet 192.168.127.0/24, gateway 192.168.127.1 |
| `Get-NetNat` | **EMPTY** — no MASQUERADE rule for 192.168.127.0/24 |
| Manually `New-NetNat -InternalIPInterfaceAddressPrefix 192.168.127.0/24` then re-run | Probe still hangs — no improvement |

The host also has a Forticlient FSE deployment installed:

```
Get-NetAdapter shows:
  vEthernet (FSE HostVnic)              Up
hnsdiag list networks shows:
  FSE Switch (Wi-Fi 5)        Mirrored
  FSE Switch (Ethernet)       Mirrored
  FSE Switch (Wi-Fi 3)        Mirrored
  FSE Switch (Wi-Fi)          Mirrored
  FSE Switch (Loopback Pseudo-Interface 1)  Mirrored
```

These "Mirrored" Hyper-V switches wrap the host's physical NICs and pass
all traffic through the Forticlient driver stack.

## Working hypotheses (NOT verified)

> Each of the following is a hypothesis to investigate, not a
> conclusion. Listed in rough order of how much they would explain.

### H1 — Forticlient FSE silently drops the NAT'd egress

- The host has working internet, but only via the FSE-mirrored switches.
- HCN NAT'd traffic from 192.168.127.x → host gets re-injected onto the
  FSE-wrapped uplink, where the FSE driver may apply a policy that drops
  packets with non-corporate source IPs.
- This would also explain why adding `New-NetNat` manually didn't help:
  even with MASQUERADE, the post-NAT source IP is the host's primary
  address, but the egress is still going through FSE which may track the
  original VM-NIC source. **Untested — would require disabling FSE and
  re-running `network_allow_all_has_nic`.**

### H2 — HCN Schema 2.x NAT did not auto-install the MASQUERADE rule

- `Get-NetNat` is empty. On a clean Windows host with HCN-Schema-2 NAT
  the platform is supposed to install a `Get-NetNat` entry automatically.
- We do not have a known-good baseline (a prior Windows host where this
  test was green AND `Get-NetNat` was populated) to compare against.
- It's possible our HCN config (`vmconfig.rs` payload) is missing a
  `Policies: [{ Type: "OutboundNat", ... }]` block that newer HCS
  builds require for the MASQUERADE rule to be installed.
  **Untested — needs reading current Microsoft HCN schema docs and
  diffing against `imp/hcn.rs::create_network_payload`.**

### H3 — Stale HCN state across runs

- We did not flush `Remove-NetNat` / `Remove-HnsNetwork` between runs.
- Possible that an older NAT rule from a previous codebase iteration is
  shadowing the current one. **Untested.**

## Scope check (why this was committed despite the failure)

The PTY commit (`feat(pty): cross-platform PTY support via ShellOpts mode
(PROTOCOL_VERSION 4)`) does not modify any code on the path exercised by
`network_allow_all_has_nic`:

```
                   PTY commit touches               unrelated to PTY
                   ───────────────────              ────────────────
host RPC layer     spawn_shell, resize_shell        (no change)
init protocol      Op::Spawn StdioMode::Pty,
                   Op::Resize, Reply types
init server        PTY allocation, master fd        (no change)
host backends      Linux/macOS/Windows shell        (no change)
                   spawn branching on opts.pty
init.sh            +/dev/pts mount block            net section unchanged
rebake scripts     +--init-sh flag                  unchanged
```

In particular `packaging/vm-image/init.sh` lines 209–238 (the network
bring-up) are untouched in this commit (verified with
`git diff packaging/vm-image/init.sh`). The HCN/HCS host-side network
code (`src/bin/tokimo-sandbox-svc/imp/hcn.rs`, `imp/vmconfig.rs`) is
also untouched.

The 4 new PTY tests pass, the 15 unrelated pre-existing tests still
pass, and the failing test does not exercise PTY at all.

## Next steps (suggested, not done)

1. **Disable Forticlient FSE** on the test host, re-run
   `cargo test --test sandbox_integration network_allow_all_has_nic`.
   If green → H1 confirmed, this is environment-only. Document in
   `tests/README.md` the FSE incompatibility.
2. If still red with FSE off → read current Microsoft HCN Schema 2.x
   docs for NAT, check whether an `OutboundNat` policy needs to be added
   to the network payload. Compare `imp/hcn.rs` to a recent MS sample.
3. Capture `pktmon` on the host vEthernet adapter while the test runs
   to see whether the SYN reaches the host and whether a SYN-ACK ever
   comes back from 1.1.1.1.

None of the above were performed in this session. All conclusions in
this document are observations and hypotheses only.
