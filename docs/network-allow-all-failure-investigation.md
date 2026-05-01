# `network_allow_all_has_nic` failure on Windows — RESOLVED

> **Status: RESOLVED (host-environment / standard-problem).**
> Root cause: the WAN-facing physical NIC on the Windows host has
> `Forwarding=Disabled` by default. HCN's NAT network only enables
> forwarding on its own `vEthernet (tokimo-sandbox-nat)` adapter, so
> reverse-NAT'd return packets cannot be routed from the WAN NIC into
> the NAT vSwitch. Outbound SYNs reach the internet, replies arrive at
> the host, but the host's IP layer drops/misroutes them and the guest
> never sees a SYN-ACK.
>
> **Fix (run once on the host as Administrator):**
>
> ```powershell
> Set-NetIPInterface -InterfaceAlias 'Ethernet' -Forwarding Enabled
> # or, less invasive per-machine equivalent:
> Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' IPEnableRouter 1
> Restart-Service RemoteAccess; Restart-Service hns
> ```
>
> After enabling forwarding on the WAN interface,
> `network_allow_all_has_nic` passes in ~3 s and the full network test
> suite is green. Treated as a **host configuration prerequisite**, not
> a code defect — `tokimo-package-sandbox` itself does not flip this
> registry/interface flag because doing so turns the user's machine
> into an IP router with broader implications. See the verification
> section at the bottom of this document for the pktmon evidence.
>
> The PTY work in
> [PROTOCOL_VERSION 4](../plan/pty-api-cross-platform.md) was committed
> with this test failing because the failure path does not touch any
> code modified by the PTY work — see "Scope check" below.

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

## Resolution & verification (added later)

The investigation continued in a follow-up session. The summary:

### What turned out to matter (and how it was found)

| Step | Finding |
|---|---|
| Rebake initrd with current `init.sh` | Old initrd was missing the `hv_netvsc` / `failover` / `net_failover` / `virtio_net` module loads. After `pwsh scripts/rebake-initrd.ps1 -InstallToVm`, the guest console showed `tokimo-init: insmod hv_netvsc OK` and eth0 came up at 192.168.127.2/24. **Necessary, not sufficient.** |
| Add `OutBoundNAT` endpoint policy | `src/bin/tokimo-sandbox-svc/imp/hcn.rs::create_endpoint()` now emits `"Policies":[{"Type":"OutBoundNAT","Settings":{}}]` between `IpConfigurations` and `Routes`. After this, **outbound** NAT works (verified with pktmon: VM→1.1.1.1 SYNs leave the WAN NIC with the host's source IP). **Necessary, not sufficient.** |
| Capture pktmon on all NICs while running the diag test | Showed: SYN out OK, SYN-ACK arrives back at the WAN NIC OK, host reverse-NATs it (`1.1.1.1 > 192.168.127.2 [S.]`), but then **forwards the post-NAT'd packet back out the same physical NIC** (TTL decremented, dst MAC = the LAN router) instead of into `vEthernet (tokimo-sandbox-nat)`. Host pings to 192.168.127.1 (its own NAT gateway IP) get no reply at all. |
| `Get-NetIPInterface` audit | `vEthernet (tokimo-sandbox-nat)` had `Forwarding=Enabled` (auto-set by HCN). Every other interface — including the WAN-facing physical `Ethernet` and `vEthernet (Default Switch)` — was `Forwarding=Disabled`. `HKLM\...\Tcpip\Parameters\IPEnableRouter` was unset (effective default 0). |
| Run `Set-NetIPInterface -InterfaceAlias 'Ethernet' -Forwarding Enabled`, re-run test | `network_allow_all_has_nic` passes in 2.93 s. Full Windows network suite (`network_allow_all_has_nic` + `network_blocked_only_loopback`) green in 5.80 s. |

### Why the working hypotheses above were wrong

- **H1 (Forticlient FSE drops it).** FSE is present on the test host but
  is *not* the cause. With WAN forwarding enabled and FSE still
  installed, the test passes. FSE filters/mirrors but does not interfere
  with HCN NAT return routing on this host.
- **H2 (HCN didn't install MASQUERADE).** HCN does install the
  `OutBoundNAT` rule, but only inside the VFP layer for the NAT
  vSwitch. That handles the rewrite. The reason packets did not reach
  the guest was the *next* hop after rewrite — the host IP layer's
  forwarding decision — which is governed by per-interface
  `Forwarding` / global `IPEnableRouter`, not by NAT state.
- **H3 (stale HCN state).** Not a factor. Tear-down/recreate did not
  change the symptom; only the forwarding flag did.

### Why the fix is documented, not coded

`tokimo-package-sandbox` does **not** flip `Forwarding=Enabled` on the
user's WAN NIC, because that turns the host into an IP router. That is
a security/operational decision for the operator, not a library. The
service-side code (`hcn.rs`, `vmconfig.rs`) emits the correct HCN
config; everything past the NAT vSwitch is the host's IP stack and is
out of scope.

The fix is therefore a **deployment prerequisite** captured in
`tests/README.md` and the top-of-file note on this document.

### Repro / one-liner

If `network_allow_all_has_nic` fails on a Windows host with the symptom
"`exec 3<>/dev/tcp/...` hangs past 5 s and the probe text is just
`NET_PROBE_DONE`", check:

```powershell
Get-NetIPInterface -AddressFamily IPv4 |
  Where-Object { $_.InterfaceAlias -in 'Ethernet','Wi-Fi' -and $_.ConnectionState -eq 'Connected' } |
  Format-Table InterfaceAlias,Forwarding -AutoSize
```

If the connected WAN interface shows `Forwarding=Disabled`, run
(elevated):

```powershell
Set-NetIPInterface -InterfaceAlias '<WAN-alias>' -Forwarding Enabled
```

and re-run the test. No reboot required.

A diagnostic test `network_allow_all_diag` is kept as `#[ignore]` in
`tests/sandbox_integration.rs` for future investigations and is invoked
with:

```powershell
cargo test --test sandbox_integration network_allow_all_diag -- --ignored --test-threads=1 --nocapture
```
