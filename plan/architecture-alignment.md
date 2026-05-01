# Tokimo vs Claude 架构对齐表

## 命令层对齐

| Claude 命令 | Claude 地址 | Tokimo 等价 | Tokimo 地址 | 状态 | 需要的 API |
|---|---|---|---|---|---|
| `configure` | `dispatchVerified` @ 0x8a90c0 | — | — | **缺失** | `HcsModifyComputeSystem` |
| `createVM` | `handleCreateVM` @ 0x8ac260 | `OpenSession` (一步到位) | `handle_open_session` | **可合并** | `HcsCreateComputeSystem` |
| `startVM` | `handleStartVM` @ 0x8ac440 | `OpenSession` (一步到位) | `handle_open_session` | **可合并** | `HcsStartComputeSystem` |
| `stopVM` | `handleStopVM` @ 0x8ace20 | pipe 断开自动销毁 | tunnel EOF | **缺失** | `HcsShutDownComputeSystem` → `HcsTerminateComputeSystem` |
| `isRunning` | `handleIsRunning` @ 0x8acf80 | — | — | **缺失** | `HcsGetComputeSystemProperties` |
| `isGuestConnected` | `IsGuestConnected` @ 0x896900 | — | — | **缺失** | RPC server 连接状态 |
| `isProcessRunning` | `handleIsProcessRunning` @ 0x8ad640 | — | — | **缺失** | guest RPC `isProcessRunning` |
| `writeStdin` | `handleWriteStdin` @ 0x8ad460 | tunnel mode (raw bytes) | `init_client.write()` | 不同实现 | — |
| `subscriptions` | `handleSubscription` @ 0x8a7980 | — | — | **缺失** | `tokio::broadcast` channel |
| `createDiskImage` | `handleCreateDiskImage` @ 0x8ac700 | — | — | **缺失** | `CreateVirtualDisk` Win32 API |
| `setDebugLogging` | `handleSetDebugLogging` @ 0x8ad840 | — | — | **缺失** | — |
| `isDebugLoggingEnabled` | `handleIsDebugLoggingEnabled` @ 0x8ad9e0 | — | — | **缺失** | — |
| `sendGuestResponse` | `handleSendGuestResponse` @ 0x8ad240 | — | — | **缺失** | guest RPC 转发 |
| `persistentRPC` | `handlePersistentRPC` @ 0x8a6740 | — | — | **缺失** | HvSocket 双向 RPC |
| `handlePassthrough` | `handlePassthrough` @ 0x8adac0 | — | — | **缺失** | guest RPC 转发 |
| — | — | `Ping` | protocol.rs | Tokimo 独有 | — |
| — | — | `ExecVm` (one-shot) | protocol.rs | Tokimo 独有 | — |
| — | — | `OpenSession` (v2) | protocol.rs | Tokimo 独有 | — |

## VM 管理层对齐

| Claude 函数 | 地址 | Tokimo 等价 | 状态 |
|---|---|---|---|
| `SetOwner` | 0x88e420 | — | **缺失** |
| `SetVHDXPath` | 0x88e760 | `find_rootfs_vhdx()` | 隐式 |
| `SetMemoryMB` | 0x88eb20 | `TOKIMO_MEMORY` env var | 硬编码 |
| `SetCPUCount` | 0x88eda0 | `TOKIMO_CPUS` env var | 硬编码 |
| `SetKernelPath` | 0x88f1c0 | `find_kernel()` | 隐式 |
| `SetInitrdPath` | 0x88f560 | `find_initrd()` | 隐式 |
| `SetSmolBinPath` | 0x88f900 | — | **缺失** (guest helper) |
| `SetSessionDiskPath` | 0x88fca0 | — | **缺失** (per-session VHDX) |
| `SetCondaDiskPath` | 0x890040 | — | **缺失** (conda env VHDX) |
| `SetAPIProbeURL` | 0x88f020 | — | **缺失** |
| `AddPlan9Share` | 0x890640 | `ShareSpec` in OpenSession | 静态 |
| `SetUserToken` | 0x891660 | — | **缺失** |
| `SetEventCallbacks` | 0x891840 | — | **缺失** |
| `CreateVM` | 0x896fc0 | `handle_open_session` | 合并 |
| `StartVM` | 0x891b40 | `handle_open_session` | 合并 |
| `StopVM` | 0x8958e0 | tunnel EOF → terminate | 隐式 |
| `IsRunning` | 0x8963c0 | — | **缺失** |
| `IsGuestConnected` | 0x896900 | — | **缺失** |
| `IsProcessRunning` | 0x8975c0 | — | **缺失** |
| `CleanupStaleVMs` | 0x88db80 | — | **缺失** |
| `BuildHCSDocument` | 0x87f660 | `vmconfig::build_session_v2` | 已有 |

## RPC Server 层对齐

| Claude 函数 | 地址 | Tokimo 等价 | 状态 |
|---|---|---|---|
| `RPCServer.Start` | 0x897a20 | — | **缺失** |
| `RPCServer.Stop` | 0x897c80 | — | **缺失** |
| `RPCServer.IsConnected` | 0x897e00 | — | **缺失** |
| `RPCServer.acceptLoop` | 0x897f20 | `hvsock::accept_guest` | 单次 |
| `RPCServer.handleConnection` | 0x898440 | tunnel mode | 不同 |
| `RPCServer.handleMessage` | 0x8989c0 | — | **缺失** |
| `RPCServer.SendRequestAndWait` | 0x89a880 | — | **缺失** |
| `RPCServer.SendNotification` | 0x89b040 | — | **缺失** |
| `RPCServer.handleResponse` | 0x898f00 | — | **缺失** |
| `RPCServer.handleEvent` | 0x899260 | — | **缺失** |
| `RPCServer.SendGuestResponse` | 0x898d40 | — | **缺失** |

## 网络层对齐

| Claude 函数 | 地址 | Tokimo 等价 | 状态 |
|---|---|---|---|
| `InitHCN` | 0x8821c0 | — | **缺失** |
| `EnumerateNetworks` | 0x882660 | — | **缺失** |
| `OpenNetwork` | 0x882c80 | — | **缺失** |
| `DeleteNetwork` | 0x883040 | — | **缺失** |
| `GetNetworkInfo` | 0x8836c0 | — | **缺失** |
| `VirtualNetworkProvider.Start` | 0x89c0c0 | — | **缺失** |
| `VirtualNetworkProvider.acceptLoop` | 0x89c580 | — | **缺失** |
| `VirtualNetworkProvider.Stop` | 0x89cdc0 | — | **缺失** |
| `sendHostProxyConfig` | 0x888f20 | — | **缺失** |
| `resolveWPADAndResend` | 0x889640 | — | **缺失** |

## HCS API 层对齐

| API | Claude 使用 | Tokimo 使用 | 状态 |
|---|---|---|---|
| `HcsCreateComputeSystem` | `CreateComputeSystem` @ 0x8846a0 | `hcs.rs` | **已有** |
| `HcsStartComputeSystem` | `HCSSystem.Start` @ 0x885760 | `hcs.rs` | **已有** |
| `HcsTerminateComputeSystem` | `HCSSystem.Terminate` @ 0x886580 | `hcs.rs` | **已有** |
| `HcsCloseComputeSystem` | `HCSSystem.Close` @ 0x886ac0 | `hcs.rs` | **已有** |
| `HcsGetComputeSystemProperties` | `HCSSystem.GetProperties` @ 0x886c20 | `hcs.rs` | **已有** |
| `HcsCreateOperation` | `InitHCS` @ 0x883ac0 | `hcs.rs` | **已有** |
| `HcsCloseOperation` | `InitHCS` @ 0x883ac0 | `hcs.rs` | **已有** |
| `HcsWaitForOperationResult` | `InitHCS` @ 0x883ac0 | `hcs.rs` | **已有** |
| `HcsModifyComputeSystem` | `HCSSystem.ModifyComputeSystem` @ 0x8874a0 | — | **缺失** |
| `HcsShutDownComputeSystem` | `HCSSystem.Shutdown` @ 0x886020 | — | **缺失** |
| `HcsEnumerateComputeSystems` | `EnumerateComputeSystems` @ 0x888240 | — | **缺失** |

## HCN API 层对齐

| API | Claude 使用 | Tokimo 使用 | 状态 |
|---|---|---|---|
| `HcnOpenNetwork` | `OpenNetwork` @ 0x882c80 | — | **缺失** |
| `HcnCloseNetwork` | `HCNNetwork.Close` @ 0x882f60 | — | **缺失** |
| `HcnDeleteNetwork` | `DeleteNetwork` @ 0x883040 | — | **缺失** |
| `HcnQueryNetworkProperties` | `HCNNetwork.GetProperties` @ 0x8833c0 | — | **缺失** |
| `HcnEnumerateNetworks` | `EnumerateNetworks` @ 0x882660 | — | **缺失** |
| `HcnCreateEndpoint` | `VirtualNetworkProvider.Start` | — | **缺失** |
| `HcnModifyEndpoint` | `VirtualNetworkProvider.Start` | — | **缺失** |

## 统计

| 类别 | 已有 | 缺失 | 总计 |
|---|---|---|---|
| 命令层 | 3 (Ping, ExecVm, OpenSession) | 14 | 17 |
| VM 管理层 | 4 (隐式) | 11 | 15 |
| RPC Server | 1 (hvsock accept) | 10 | 11 |
| 网络层 | 0 | 10 | 10 |
| HCS API | 8 | 3 | 11 |
| HCN API | 0 | 7 | 7 |
| **总计** | **16** | **55** | **71** |

## 实现优先级

### P0 (核心功能，必须先做)
1. `HcsModifyComputeSystem` — 运行时配置变更的基础
2. `HcsShutDownComputeSystem` — 优雅关机
3. `HcsEnumerateComputeSystems` — 崩溃恢复
4. 持久连接协议 — 多命令复用
5. VM 状态管理器 — `CreateVM` / `StartVM` / `StopVM` 分离
6. `configure` 命令 — 运行时设置 memory/CPU/shares/network

### P1 (网络，最大用户感知差距)
7. HCN API 全套 — `AllowAll` 网络策略
8. `sendHostProxyConfig` — WPAD/PAC 代理转发
9. `VirtualNetworkProvider` — gvisor/netstack 或 smoltcp

### P2 (事件与查询)
10. 事件订阅系统 — `subscriptions` 命令
11. 状态查询 — `isRunning` / `isGuestConnected` / `isProcessRunning`
12. 空闲超时 — 自动关闭无 subscriber 的 VM

### P3 (高级功能)
13. RPC Server — 持久 guest daemon 通信
14. `CreateDiskImage` — 动态磁盘创建
15. `SetDebugLogging` — 运行时日志切换
16. `handlePassthrough` — 任意命令转发到 guest
