# Plan: Upgrade Windows Service to Production-Grade Architecture

## Context

Tokimo Windows service 当前是功能原型。Claude 的 cowork-svc.exe 是完整的 VM 平台。目标：对齐 Claude 能力，性能更好。

**参考文档**:
- `plan/architecture-alignment.md` — API 对齐表 + 优先级
- `plan/command-implementation-details.md` — 每个命令的实现细节

## Implementation Phases

### Phase 1: Protocol Upgrade (Foundation)
**Files**: `src/windows/protocol.rs`, `src/bin/tokimo-sandbox-svc/imp/mod.rs`, `src/windows/client.rs`

Upgrade the wire protocol from request-response to persistent command-based.

**Claude's approach**: 按字符串长度 + memequal 分发 (O(1))，持久连接，未知命令透传到 guest。

1. **新命令**: 对齐 Claude 的 14 个命令 (详见 `architecture-alignment.md`)
2. **持久连接**: pipe 不再断开，多命令复用
3. **向后兼容**: 协议版本升到 3，V2 客户端仍可用

### Phase 2: VM State Manager
**New file**: `src/bin/tokimo-sandbox-svc/imp/vm_manager.rs`

Central VM lifecycle manager replacing the ad-hoc per-connection VM creation.

**Claude's approach** (from decompiled `WindowsVMManager`):
- Configuration is a **builder chain**: `SetOwner → SetVHDXPath → SetMemoryMB → SetCPUCount → SetKernelPath → SetInitrdPath → SetSmolBinPath → SetSessionDiskPath → SetCondaDiskPath → AddPlan9Share → SetUserToken → SetEventCallbacks`
- `CreateVM` builds HCS JSON + `HcsCreateComputeSystem` + grants VM access to all artifacts
- `StartVM` starts HCS + console reader + RPC server + VNet + sends proxy config + installs CA certs
- `StopVM` stops console reader + RPC server + VNet + `HcsShutdownComputeSystem` (with timeout fallback to `HcsTerminateComputeSystem`)
- `CleanupStaleVMs` uses `HcsEnumerateComputeSystems` to find and clean orphaned VMs

1. **`VmManager` struct**: Owns all running VMs, keyed by session ID.
   - `sessions: HashMap<String, SessionState>` — tracks VM handle, HvSocket connections, subscribers, idle timer
   - `SessionState`: `{ cs_handle, init_port, share_ports, hvsock_conn, subscribers: Vec<Sender<Event>>, idle_deadline, config }`

2. **VM lifecycle**: Create → Start → Running (accept connections) → Idle timeout → Stop → Destroy
   - Idle timeout: configurable (default 5 min). Reset on any command. When expired, terminate VM.
   - Graceful shutdown: HcsShutdownComputeSystem → 5s grace → HcsTerminateComputeSystem

3. **Session multiplexing**: Multiple clients can connect to the same session (read-only observers + one writer). Claude does this with their subscriber system.

4. **Crash recovery**: On service start, call `HcsEnumerateComputeSystems` to scan for orphaned systems. Claude's `isOurVM()` checks VM ID format; `isCurrentFormatVMID()` validates the format. Clean up any stale VMs.

5. **HCS Modify**: `HcsModifyComputeSystem(handle, resourcePath, settingsJson)` for runtime changes:
   - Plan9 shares: resource path `"VirtualMachine/Devices/Plan9/Shares"`
   - Memory/CPU: resource path `"VirtualMachine/ComputeTopology"`

### Phase 3: Event Subscription System
**New file**: `src/bin/tokimo-sandbox-svc/imp/events.rs`

实现细节见 `command-implementation-details.md` 第 9 节 `subscriptions`。

1. **Event channel**: `make(chan *Event, 100)` 带缓冲
2. **Subscriber map**: `session.subscribers[conn] = eventChan`，`RWMutex` 保护
3. **Idle timeout**: 最后一个 subscriber 断开后开始计时
4. **Event broadcast**: 遍历 subscribers，channel 满则丢弃并日志警告

### Phase 4: Networking (HCN + Userspace Netstack)
**New file**: `src/bin/tokimo-sandbox-svc/imp/netstack.rs`

**Claude's actual approach** (from reverse engineering):
- Uses **HCN** (Host Compute Network) via `computenetwork.dll` for the virtual switch/network
- Uses **gvisor netstack** (Go) for userspace TCP/IP forwarding between vsock and host network
- `VirtualNetworkProvider` manages the lifecycle: HCN network creation → gvisor netstack → vsock listener
- Guest connects via vsock, traffic flows: `Guest ↔ vsock ↔ gvisor netstack ↔ host sockets ↔ Internet`
- **WPAD/PAC proxy** auto-detection and forwarding to guest
- HCN APIs used: `HcnOpenNetwork`, `HcnQueryNetworkProperties`, `HcnEnumerateNetworks`, `HcnDeleteNetwork`, `HcnCreateEndpoint`

1. **HCN for AllowAll** (quick win):
   - Load `computenetwork.dll` dynamically (like Claude's `InitHCN` @ 0x8821c0)
   - Create HCN network with subnet/gateway/MTU
   - Attach endpoint to HCS compute system
   - Guest gets a real NIC with NAT — no userspace forwarding needed

2. **Userspace netstack for Observed/Gated** (packet inspection):
   - Add `smoltcp` crate (Rust equivalent of gvisor netstack, ~100KB vs ~5MB)
   - Create vsock listener, accept VM connections
   - Forward TCP/UDP via smoltcp: `Guest → vsock → smoltcp → host sockets`
   - HTTP proxy: intercept HTTP/HTTPS CONNECT tunnels (reuse `host/net_observer.rs` patterns)
   - DNS proxy: intercept DNS queries, forward to host resolver

3. **WPAD/PAC proxy** (Claude's `sendHostProxyConfig` @ 0x888f20):
   - Read Windows proxy settings from registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
   - Detect PAC URL via `WinHttpGetIEProxyConfigForCurrentUser`
   - Fetch PAC script, send to guest via RPC
   - Guest applies proxy config for outbound HTTP/HTTPS

4. **Network policy mapping**:
   - `Blocked` → no NIC (current behavior)
   - `AllowAll` → HCN NAT endpoint (fast path)
   - `Observed` → userspace netstack + HTTP proxy + DNS proxy
   - `Gated` → Observed + host allowlist enforcement

### Phase 5: Dynamic Plan9 Reconfiguration
**File**: `src/bin/tokimo-sandbox-svc/imp/mod.rs`, `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs`

**Claude's approach** (from decompiled `AddPlan9Share` @ 0x890640 + `HCSSystem.AddPlan9Share` @ 0x888060):
- `HcsModifyComputeSystem(handle, "VirtualMachine/Devices/Plan9/Shares", json)` to add shares at runtime
- `sendPlan9Shares()` @ 0x8912e0 notifies guest daemon via RPC to mount the new share
- Logs: `"[VM] Plan9 share added: %s -> %s (port=%d, readOnly=%v)"`

1. **`AddPlan9Share`**: Allocate a new vsock port, register in HCS config via `HcsModifyComputeSystem(handle, "VirtualMachine/Devices/Plan9/Shares", settingsJson)`, send `MountManifest` update to guest init via HvSocket.

2. **`RemovePlan9Share`**: Send unmount request to guest, remove from HCS config via `HcsModifyComputeSystem`, deallocate port.

3. **Guest-side**: Init already handles `MountManifest` — extend it to handle incremental mount/unmount updates on the existing connection.

### Phase 6: Resource Limits Enforcement
**File**: `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs`, `src/windows/session.rs`

1. **Memory**: Set HCS `Memory.maximum` from `cfg.limits.max_memory_mb` (currently hardcoded 2048).

2. **CPU**: Set HCS `ProcessorCount` from `cfg.limits.max_processes` or new `cpu_count` field (currently hardcoded 2).

3. **Timeout**: Enforce `cfg.limits.timeout_secs` as a watchdog in the service (terminate VM after timeout).

4. **File size**: Enforce in guest via init's seccomp filter or cgroup limits.

### Phase 7: Guest Daemon (Optional, for Persistent RPC)
**New binary**: `src/bin/tokimo-sandbox-daemon/`

A long-running guest-side daemon that maintains a persistent RPC channel to the host service.

1. **When to use**: Only for advanced use cases (Claude's sdk-daemon for real-time bidirectional communication). The per-session init model is sufficient for most sandbox use cases.

2. **RPC protocol**: JSON-RPC over HvSocket. Methods: `Execute`, `WriteStdin`, `ReadOutput`, `GetProcessStatus`, `ConfigureNetwork`, `InstallCertificates`.

3. **Boot**: Pass `tokimo.daemon=1` on kernel cmdline. Init spawns the daemon and hands off the HvSocket.

### Phase 8: Authenticode & Security Hardening
**File**: `src/bin/tokimo-sandbox-svc/imp/mod.rs`

**Claude's approach** (from decompiled functions):
- `InitSignatureVerification` @ 0x8a10e0: loads signing cert from service exe at startup
- `verifyClientSignature` @ 0x8a1fc0: for each connection, verifies client exe via `WinVerifyTrust`
- `VerifySignature` @ 0x8adbe0: the actual WinVerifyTrust call + cert info extraction
- `getSigningCertificateInfo` @ 0x8ae140: extracts subject, thumbprint from signing cert
- Logs: `"[Server] Client signature verified: %s (subject: %s)"` or `"client signature is invalid for %s: %s"`
- Service SID type: `ServiceSidType = 1` (RESTRICTED) — confirmed from registry

1. **Default-on verification**: Change `TOKIMO_VERIFY_CALLER` to opt-out (verify by default, `TOKIMO_SKIP_VERIFY=1` to bypass).

2. **Certificate pinning**: Allow pinning specific publisher CNs in registry.

3. **Pipe ACL tightening**: Remove Interactive Users write access in production (MSIX mode only).

4. **Service SID**: Set `ServiceSidType = 1` (RESTRICTED) like Claude does, for defense-in-depth.

## Implementation Order & Dependencies

```
Phase 1 (Protocol) ──► Phase 2 (VM Manager) ──► Phase 3 (Events)
                                                        │
                           Phase 4 (Networking) ◄───────┘
                                │
                           Phase 5 (Dynamic Plan9)
                                │
                           Phase 6 (Resource Limits)
                                │
                    ┌───────────┴───────────┐
                    │                       │
              Phase 7 (Daemon)       Phase 8 (Security)
```

**Critical path**: Phase 1 → Phase 2 → Phase 4 (networking is the biggest user-visible gap)
**Parallel work**: Phase 6 can start as soon as Phase 2 is done. Phase 8 is independent.

## Files to Modify/Create

| Action | File | Phase |
|---|---|---|
| Modify | `src/windows/protocol.rs` | 1 |
| Modify | `src/bin/tokimo-sandbox-svc/imp/mod.rs` | 1, 2, 5 |
| Modify | `src/windows/client.rs` | 1 |
| Modify | `src/windows/init_client.rs` | 5 |
| Modify | `src/windows/session.rs` | 6 |
| Modify | `src/config.rs` | 6 |
| Modify | `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs` | 5, 6 |
| Create | `src/bin/tokimo-sandbox-svc/imp/vm_manager.rs` | 2 |
| Create | `src/bin/tokimo-sandbox-svc/imp/events.rs` | 3 |
| Create | `src/bin/tokimo-sandbox-svc/imp/netstack.rs` | 4 |
| Modify | `src/bin/tokimo-sandbox-init/main.rs` | 5, 7 |
| Modify | `src/bin/tokimo-sandbox-init/server.rs` | 5, 7 |
| Create | `src/bin/tokimo-sandbox-daemon/` | 7 |
| Modify | `Cargo.toml` | 4 (add smoltcp or hcn deps) |

## Performance Advantages over Claude

1. **Rust vs Go**: Zero GC pauses, lower memory footprint, predictable latency
2. **No gvisor overhead**: smoltcp is ~100KB vs gvisor's ~5MB compiled
3. **Direct HCS FFI**: No CGo overhead for HCS calls
4. **Overlapped I/O**: Already have proper async pipe I/O; Go uses goroutines which have scheduling overhead
5. **Zero-copy tunnel**: The bidirectional tunnel can use `splice`-equivalent patterns

## Verification Plan

1. **Unit tests**: New protocol types, VM manager state machine, event bus
2. **Integration tests**: Extend `tests/multi_mount.rs` with new commands
3. **Concurrency tests**: Multiple clients connecting to same session, subscriber stress test
4. **Network tests**: `curl` from guest with each policy (Blocked, AllowAll, Observed, Gated)
5. **Idle timeout test**: Verify VM auto-shuts down after timeout, restarts on demand
6. **Crash recovery test**: Kill service mid-session, restart, verify orphan cleanup
7. **Performance benchmark**: Compare session startup time vs Claude's service
