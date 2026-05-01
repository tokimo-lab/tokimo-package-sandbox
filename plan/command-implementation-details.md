# Claude cowork-svc.exe 每个命令的实现细节

基于 IDA Pro 反编译，以下是每个命令的完整实现流程。

---

## 1. `configure` — 运行时配置 VM

**入口**: `dispatchVerified` @ 0x8a90c0 (在 session 创建前调用)
**Handler**: `handleConfigure` @ 0x8a9fa0

### 流程
```
1. JSON Unmarshal → ConfigureParams
2. GetClientInfoFromConn(conn) → ClientInfo (user SID, exe path, token)
3. verifyClientSignature(info) — Authenticode 验证
4. UserDataDirFor(info, params.UserDataName) → 用户数据目录
5. getOrCreateSession(server, username, userDataDir) → vmSession
6. 设置 session 配置:
   ├─ SetOwner(owner SID)
   ├─ SetVHDXPath(params.VHDXPath)
   ├─ SetMemoryMB(params.MemoryMB)
   ├─ SetCPUCount(params.CPUCount)
   ├─ SetKernelPath(params.KernelPath)
   ├─ SetInitrdPath(params.InitrdPath)
   ├─ SetSmolBinPath(params.SmolBinPath)
   ├─ SetSessionDiskPath(params.SessionDiskPath)
   ├─ SetCondaDiskPath(params.CondaDiskPath)
   ├─ SetAPIProbeURL(params.APIProbeURL)
   ├─ for each share in params.Plan9Shares:
   │   └─ AddPlan9Share(share.Name, share.Path, share.ReadOnly)
   ├─ SetUserToken(clientToken)
   └─ SetEventCallbacks(callbacks)
7. session.setConfigured(true)
8. 写响应到 pipe
```

### ConfigureParams 结构
```go
type ConfigureParams struct {
    UserDataName    string           // 用户标识
    VHDXPath        string           // rootfs VHDX 路径
    MemoryMB        int              // 内存 MB
    CPUCount        int              // CPU 核数
    KernelPath      string           // vmlinuz 路径
    InitrdPath      string           // initrd 路径
    SmolBinPath     string           // guest helper binary
    SessionDiskPath string           // per-session 可写 VHDX
    CondaDiskPath   string           // conda 环境 VHDX
    APIProbeURL     string           // API 可达性检查 URL
    Plan9Shares     []Plan9ShareInfo // Plan9 共享列表
}
```

---

## 2. `createVM` — 创建 HCS 计算系统

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 8)
**Handler**: `handleCreateVM` @ 0x8ac260
**VM 方法**: `WindowsVMManager.CreateVM` @ 0x896fc0

### 流程
```
1. JSON Unmarshal → CreateVMParams { BundlePath, DiskSizeGB }
2. WindowsVMManager.CreateVM(bundlePath, diskSizeGB)
   ├─ BuildHCSDocument() @ 0x87f660
   │   └─ 生成 HCS Schema 2.x JSON (见下文)
   ├─ CreateComputeSystem(id, json) @ 0x8846a0
   │   └─ HcsCreateComputeSystem(id, config, op, secDesc, &handle)
   ├─ grantVMAccess(handle, kernelPath) @ 0x88d860
   ├─ grantVMAccess(handle, initrdPath)
   ├─ grantVMAccess(handle, vhdxPath)
   ├─ grantVMAccess(handle, smolBinPath)
   ├─ grantVMAccess(handle, sessionDiskPath)
   └─ grantVMAccess(handle, condaDiskPath)
3. 返回 success/error
```

### CreateVMParams 结构
```go
type CreateVMParams struct {
    BundlePath string // VM bundle 路径 (含 kernel, initrd, rootfs)
    DiskSizeGB int    // 磁盘大小 GB
}
```

### grantVMAccess 实现
调用 `icacls` 或 `SetNamedSecurityInfoW` 给 VM 进程的 SID 授予文件读取权限。

---

## 3. `startVM` — 启动 VM

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 7)
**Handler**: `handleStartVM` @ 0x8ac440
**VM 方法**: `WindowsVMManager.StartVMWithBundle` @ 0x897140

### 流程
```
1. JSON Unmarshal → StartVMParams { BundlePath, MemoryGB, CPUCount, APIProbeURL }
2. context.WithTimeout(ctx, timeout)
3. WindowsVMManager.StartVMWithBundle(ctx, bundlePath, memoryGB, cpuCount, apiProbeURL)
   ├─ 设置 MemoryMB, CPUCount
   ├─ BuildHCSDocument() → HCS JSON
   ├─ CreateComputeSystem(id, json)
   ├─ grantVMAccess 对所有文件
   ├─ HCSSystem.Start() @ 0x885760
   │   └─ HcsStartComputeSystem(handle, op, NULL)
   ├─ ConsoleReader.Start() @ 0x880e60
   │   └─ 连接 COM1/COM2 named pipe, 启动 readLoop goroutine
   ├─ RPCServer.Start() @ 0x897a20
   │   └─ 启动 HvSocket listener, 等待 guest daemon 连接
   ├─ VirtualNetworkProvider.Start() @ 0x89c0c0 (如果配置了网络)
   │   └─ 创建 HCN 网络 + gvisor netstack + vsock listener
   ├─ installHostCACertificates() @ 0x896a40
   │   └─ 从 Windows ROOT+CA 证书存储加载证书
   │   └─ 通过 RPC 发送给 guest daemon 安装
   └─ sendHostProxyConfig() @ 0x888f20
       ├─ loadWinINetProxy() — 读 Windows 代理设置
       ├─ readAutoConfigURL() — 读 PAC URL
       ├─ resolveWPADAndResend() — WPAD 自动发现
       └─ 通过 RPC 发送代理配置给 guest
4. 返回 success/error
```

### StartVMParams 结构
```go
type StartVMParams struct {
    BundlePath  string // VM bundle 路径
    MemoryGB    int    // 内存 GB
    CPUCount    int    // CPU 核数
    APIProbeURL string // API 可达性检查 URL
}
```

---

## 4. `stopVM` — 停止 VM

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 6)
**Handler**: `handleStopVM` @ 0x8ace20
**VM 方法**: `WindowsVMManager.StopVM` @ 0x8958e0

### 流程
```
1. context.WithTimeout(ctx, timeout)
2. WindowsVMManager.StopVM(ctx)
   ├─ stopConsoleReader() @ 0x8955e0
   │   └─ 关闭 COM pipe, 停止 readLoop goroutine
   ├─ RPCServer.Stop() @ 0x897c80
   │   └─ 关闭 HvSocket listener, 断开所有连接
   ├─ VirtualNetworkProvider.Stop() @ 0x89cdc0
   │   └─ 关闭 vsock listener, 停止 gvisor netstack
   ├─ HCSSystem.Shutdown() @ 0x886020
   │   └─ HcsShutDownComputeSystem(handle, op, NULL)
   │   └─ 如果超时 (guest 没有响应 ACPI shutdown):
   │       └─ HCSSystem.Terminate() @ 0x886580
   │           └─ HcsTerminateComputeSystem(handle, op, NULL)
   ├─ HCSSystem.Close() @ 0x886ac0
   │   └─ HcsCloseComputeSystem(handle)
   └─ releaseResources() @ 0x8957e0
       └─ 清理所有分配的资源
3. 返回 success/error
```

---

## 5. `isRunning` — 查询 VM 状态

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 9)
**Handler**: `handleIsRunning` @ 0x8acf80
**VM 方法**: `WindowsVMManager.IsRunning` @ 0x8963c0

### 流程
```
1. WindowsVMManager.IsRunning()
   └─ HCSSystem.GetProperties() @ 0x886c20
       └─ HcsGetComputeSystemProperties(handle, op, query)
       └─ 解析 JSON: {"State":"Running"} 或 {"Stopped":true}

2. 如果 !IsRunning && HasUnreleasedResources:
   └─ 自动调用 StopVM() 清理
       └─ 日志: "[Server] Warning: crash cleanup failed for %s:%s: %v"

3. 返回 IsRunningResult { Running: bool }
```

### 关键逻辑
`isRunning` 不仅查询状态，还会**自动清理崩溃的 VM**。如果 VM 已经停止但资源未释放，会调用 `StopVM()` 进行清理。

---

## 6. `isGuestConnected` — 查询 Guest Daemon 连接状态

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 16)
**直接调用**: `WindowsVMManager.IsGuestConnected` @ 0x896900

### 流程
```
1. WindowsVMManager.IsGuestConnected()
   └─ RPCServer.IsConnected() @ 0x897e00
       └─ 检查 HvSocket 连接是否活跃
2. 返回 IsGuestConnectedResult { Connected: bool }
```

---

## 7. `isProcessRunning` — 查询 Guest 内进程状态

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 16, 第二个匹配)
**Handler**: `handleIsProcessRunning` @ 0x8ad640
**VM 方法**: `WindowsVMManager.IsProcessRunning` @ 0x8975c0

### 流程
```
1. JSON Unmarshal → IsProcessRunningParams { ID }
2. WindowsVMManager.IsProcessRunning(id)
   └─ 通过 RPCServer 发送请求给 guest daemon
   └─ guest daemon 检查进程是否存在
   └─ 等待响应
3. 返回 IsProcessRunningResult { Running: bool }
```

---

## 8. `writeStdin` — 写入进程 stdin

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 10)
**Handler**: `handleWriteStdin` @ 0x8ad460
**VM 方法**: `WindowsVMManager.WriteStdin` @ 0x897440

### 流程
```
1. JSON Unmarshal → WriteStdinParams { ID, Data }
2. WindowsVMManager.WriteStdin(id, data)
   └─ 通过 RPCServer 发送给 guest daemon
   └─ guest daemon 写入目标进程的 stdin
3. 返回 success/error
```

### WriteStdinParams 结构
```go
type WriteStdinParams struct {
    ID   string // 进程 ID
    Data string // base64 编码的数据
}
```

---

## 9. `subscriptions` — 事件订阅

**入口**: `handleConnection` @ 0x8a6040 (特殊处理，在 dispatch 之前)
**Handler**: `handleSubscription` @ 0x8a7980

### 流程
```
1. GetClientInfoFromConn(conn) → ClientInfo
2. verifyClientSignature(info) — Authenticode 验证
3. JSON Unmarshal → SubscribeEventsParams { UserDataName }
4. UserDataDirFor(info, userDataName) → 用户数据目录
5. getOrCreateSession(server, username, userDataDir) → vmSession
6. 写订阅确认响应到 pipe
7. 创建事件 channel: make(chan *Event, 100)  // 带缓冲，100 个事件
8. 创建完成 channel: make(chan struct{})
9. subscribersMu.Lock()
10. session.subscribers[conn] = eventChan  // 注册 subscriber
11. subscribersMu.Unlock()
12. session.lastDisconnect = zero  // 重置断开时间
13. 日志: "[Server] Event subscriber connected for %s:%s (total: %d)"
14. 启动清理 goroutine:
    └─ 等待 conn 关闭或 ctx 取消
    └─ 从 session.subscribers 删除
    └─ 日志: "[Server] Event subscriber disconnected for %s:%s (remaining: %d)"
15. 进入事件循环 (select):
    ├─ case event from eventChan:
    │   └─ WriteMessage(conn, event)
    │   └─ 如果写失败: 日志 "[Server] Failed to send event to subscriber: %v", break
    ├─ case conn closed:
    │   └─ 日志: "[Server] Subscriber connection closed by client", break
    └─ case ctx cancelled:
        └─ break
```

### SubscribeEventsParams 结构
```go
type SubscribeEventsParams struct {
    UserDataName string // 用户标识
}
```

### 事件广播机制
```
vmSession.broadcast(event) @ 0x8a0c60
  ├─ subscribersMu.RLock()
  ├─ for each (conn, chan) in subscribers:
  │   └─ select {
  │       case chan <- event:
  │       default:
  │           日志: "[Server] Warning: subscriber channel full, dropping event"
  │   }
  └─ subscribersMu.RUnlock()
```

---

## 10. `createDiskImage` — 创建 VHDX 磁盘

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 15)
**Handler**: `handleCreateDiskImage` @ 0x8ac700

### 流程
```
1. JSON Unmarshal → CreateDiskImageParams { DiskName, SizeGiB }
2. 验证 SizeGiB > 0
3. 验证 DiskName 通过正则表达式 (安全检查)
4. 构建路径:
   ├─ logDir = path.Join(session.userDataPath, "logs")
   ├─ diskPath = path.Join(session.userDataPath, DiskName + ".vhdx")
5. validateLogPath(logDir) — 确保目录安全
6. validateLogPath(diskPath) — 确保文件路径安全
7. CreateSparseVHDX(diskPath, sizeGiB << 30) @ 0x89b640
   └─ 调用 Win32 CreateVirtualDisk API 创建稀疏 VHDX
   └─ 日志: "[VHDX] Creating sparse VHDX: %s (size: %d bytes)"
8. 日志: "[Server] Created disk image: %s (%d GiB)"
9. 返回 success
```

### CreateDiskImageParams 结构
```go
type CreateDiskImageParams struct {
    DiskName string // 磁盘名称 (不含扩展名)
    SizeGiB  int    // 大小 GiB
}
```

### CreateSparseVHDX 实现
调用 `CreateVirtualDisk` Win32 API:
```cpp
CREATE_VIRTUAL_DISK_PARAMETERS_V1 {
    Version = 1,
    UniqueId = GUID,
    MaximumSize = sizeGiB * 1024 * 1024 * 1024,
    BlockSizeBytes = 0,  // default
    SectorSizeBytes = 512,
    ParentPath = NULL
}
CREATE_VIRTUAL_DISK_FLAG_SPARSE_FILE
```

---

## 11. `setDebugLogging` — 设置调试日志

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 15, 第二个匹配)
**Handler**: `handleSetDebugLogging` @ 0x8ad840

### 流程
```
1. JSON Unmarshal → SetDebugLoggingParams { Enabled }
2. server.mu.Lock()
3. server.debugLogging = params.Enabled
4. server.mu.Unlock()
5. 返回 success
```

### SetDebugLoggingParams 结构
```go
type SetDebugLoggingParams struct {
    Enabled bool
}
```

---

## 12. `isDebugLoggingEnabled` — 查询调试日志状态

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 21)
**Handler**: `handleIsDebugLoggingEnabled` @ 0x8ad9e0

### 流程
```
1. server.mu.RLock()
2. enabled = server.debugLogging
3. server.mu.RUnlock()
4. 返回 { Enabled: enabled }
```

---

## 13. `sendGuestResponse` — 转发响应到 Guest

**入口**: `dispatchWithSession` @ 0x8a94a0 (case 17)
**Handler**: `handleSendGuestResponse` @ 0x8ad240

### 流程
```
1. 获取 session 的 RPCServer
2. RPCServer.SendGuestResponse(params) @ 0x898d40
   └─ 将 host app 的响应转发给 guest daemon
   └─ guest daemon 可以据此决定下一步操作
3. 返回 success
```

---

## 14. `handlePassthrough` — 透传到 Guest

**入口**: `dispatchWithSession` @ 0x8a94a0 (passthrough map 查找)
**Handler**: `handlePassthrough` @ 0x8adac0

### 流程
```
1. 获取 session 的 WindowsVMManager
2. WindowsVMManager.ForwardToVM(command, params) @ 0x8978a0
   └─ 通过 RPCServer 发送原始命令给 guest daemon
   └─ guest daemon 处理未知命令
3. 返回 success/error
```

### 关键设计
这是一个**扩展点** — 任何未在 dispatchWithSession 中显式处理的命令都会被转发到 guest daemon。这意味着 guest daemon 可以实现自定义命令而无需修改 host service。

---

## 15. `persistentRPC` — 持久 RPC 通道

**入口**: `handleConnection` @ 0x8a6040 (在 dispatch 返回后检查)
**Handler**: `handlePersistentRPC` @ 0x8a6740

### 流程
```
1. 日志: "[Server] Persistent RPC: entering loop"
2. 进入双向消息循环:
   ├─ 从 pipe 读取请求 (ReadMessage)
   ├─ 转发给 guest daemon (RPCServer.SendGuestResponse)
   ├─ 从 guest daemon 读取响应
   └─ 转发回 pipe (WriteMessage)
3. 循环直到:
   ├─ pipe 断开
   ├─ guest daemon 断开
   └─ ctx 取消
4. 日志: "[Server] Persistent RPC: connection ended: %v"
```

### 触发条件
`handleConnection` 在 dispatch 返回后检查 `response.NeedPersistentRPC` 标志。如果为 true，则进入持久 RPC 模式。这通常在 `configure` 命令完成后触发，允许 host app 和 guest daemon 之间进行实时双向通信。

---

## 16. `getOrCreateSession` — 获取或创建 Session

**入口**: 多个 handler 调用
**方法**: `Server.getOrCreateSession` @ 0x8a2c80

### 流程
```
1. server.sessionsMu.Lock()
2. 查找 server.sessions[username+userDataDir]
3. 如果找到: 返回现有 session
4. 如果未找到:
   ├─ 创建新的 vmSession
   ├─ 初始化 subscribers map
   ├─ 初始化 subscribersMu (RWMutex)
   ├─ 初始化 mu (Mutex)
   ├─ 创建 WindowsVMManager
   ├─ server.sessions[key] = session
   └─ 返回新 session
5. server.sessionsMu.Unlock()
```

### vmSession 结构 (从逆向推断)
```go
type vmSession struct {
    mu              sync.Mutex
    subscribersMu   sync.RWMutex
    subscribers     map[net.Conn]chan *Event
    lastDisconnect  time.Time
    username        string
    userDataPath    string
    manager         *WindowsVMManager
    configured      bool
    debugLogging    bool
}
```

---

## 命令参数结构体汇总

| 命令 | 参数结构体 | 字段 |
|------|-----------|------|
| `configure` | `ConfigureParams` | UserDataName, VHDXPath, MemoryMB, CPUCount, KernelPath, InitrdPath, SmolBinPath, SessionDiskPath, CondaDiskPath, APIProbeURL, Plan9Shares |
| `createVM` | `CreateVMParams` | BundlePath, DiskSizeGB |
| `startVM` | `StartVMParams` | BundlePath, MemoryGB, CPUCount, APIProbeURL |
| `stopVM` | (无参数) | — |
| `isRunning` | (无参数) | — |
| `isGuestConnected` | (无参数) | — |
| `isProcessRunning` | `IsProcessRunningParams` | ID |
| `writeStdin` | `WriteStdinParams` | ID, Data |
| `subscriptions` | `SubscribeEventsParams` | UserDataName |
| `createDiskImage` | `CreateDiskImageParams` | DiskName, SizeGiB |
| `setDebugLogging` | `SetDebugLoggingParams` | Enabled |
| `isDebugLoggingEnabled` | (无参数) | — |
| `sendGuestResponse` | (原始 JSON) | — |

---

## 17. RPC Server — Guest Daemon 通信

### Wire Protocol (ReadMessage / WriteMessage)

**与 tokimo 完全相同**: `[4B big-endian length][JSON payload]`

`WriteMessage` @ 0x88cc20:
```
1. _byteswap_ulong(length) — 将长度转为 big-endian
2. HVSocketConn.Write(length_bytes) — 写 4 字节长度
3. HVSocketConn.Write(json_bytes) — 写 JSON payload
```

`ReadMessage` @ 0x88cd40:
```
1. HVSocketConn.Read(4 bytes) — 读 4 字节长度
2. _byteswap_ulong(length) — 从 big-endian 转回
3. HVSocketConn.Read(length bytes) — 读 JSON payload
```

**关键发现**: Claude 的 RPC wire format 是 **4B big-endian length + JSON**，tokimo 的 init protocol 也是 **4B big-endian length + JSON**。完全兼容。

### RPCServer.Start @ 0x897a20

```
1. NewHVSocketListener(vmId, port=51234) — 创建 HvSocket listener
   └─ port 51234 是 RPC 服务的固定端口
2. server.listener = listener
3. wg.Add(1)
4. go acceptLoop() — 启动 accept goroutine
5. 日志: "[RPC] Server started, waiting for sdk-daemon connection on port 51234"
```

### RPCServer.acceptLoop @ 0x897f20

```
循环:
  1. select { case <-stopCh: return } — 检查停止信号
  2. listener.Accept() — 接受 guest 连接
  3. 如果错误:
     └─ 检查 stopCh，如果已停止则 return
     └─ 日志: "[VNet] Accept error (will retry): %v"
  4. 如果成功:
     └─ GUIDToString(remoteAddr) — 获取 guest VM ID
     └─ 日志: "[HVSock] Accepted connection from VM=%s"
     └─ connMu.Lock()
     └─ 如果已有连接: CloseHandle(旧连接) — 关闭旧连接
     └─ server.conn = 新连接
     └─ server.connected = true
     └─ connMu.Unlock()
     └─ wg.Add(1)
     └─ go handleConnection(conn) — 启动 per-connection goroutine
```

**关键设计**: 只维护**一个活跃连接**。新连接会替换旧连接（CloseHandle 旧的）。

### RPCServer.handleConnection @ 0x898440

```
defer wg.Done()
defer cleanup(conn)

循环:
  1. select { case <-stopCh: return } — 检查停止信号
  2. ReadMessage(conn) → raw bytes
  3. 如果读取错误: 日志 "[RPC] Read error: %v", break
  4. JSON Unmarshal → Message struct
  5. 如果解析错误: 日志 "[RPC] Failed to parse message: %v", continue
  6. handleMessage(server, conn, msg)
```

### RPCServer.handleMessage @ 0x8989c0

按消息类型分发（**按字符串长度 + memequal**，与 pipe 命令分发相同模式）：

| 长度 | 类型 | 处理 |
|------|------|------|
| 4 | `exit` | 解析 ExitEventParams，调用 OnExit 回调 |
| 5 | `event` | → `handleEvent` |
| 6 | `stderr` | 解析 StderrEventParams，调用 OnStderr 回调 |
| 6 | `stdout` | 解析 StdoutEventParams，调用 OnStdout 回调 |
| 7 | `request` | 解析 request，调用 OnRequest 回调 |
| 8 | `response` | → `handleResponse` |

**`request` 处理**:
```
1. JSON Marshal(request.params) → params bytes
2. callback = server.OnRequest
3. 如果 callback 存在:
   └─ callback(request.method, params, request.id, request.id2)
4. 如果 callback 不存在:
   └─ 日志: "[RPC] Guest request %s but no callback registered"
   └─ SendGuestResponse(id, id2, error="not implemented")
```

### RPCServer.handleEvent @ 0x899260

按事件名分发：

| 事件名 | 参数结构体 | 回调 |
|--------|-----------|------|
| `exit` (4) | ExitEventParams { ID, Code, Signal } | `OnExit(id, code, signal)` |
| `error` (5) | ErrorEventParams { ID, Message, Fatal } | `OnError(id, message, fatal)` |
| `stderr` (6) | StderrEventParams { ID, Data } | `OnStderr(id, data)` |
| `stdout` (6) | StdoutEventParams { ID, Data } | `OnStdout(id, data)` |
| `networkStatus` (13) | NetworkStatusEventParams { Status } | `OnNetworkStatus(status)` |
| `apiReachability` (15) | ApiReachabilityEventParams { Status } | `OnApiReachability(status)` |
| `ready` (5) | (无参数) | `OnReady()` + 设置 `connected = true` |

**`ready` 事件特殊处理**:
```
1. connMu.Lock()
2. 检查 server.conn == 当前连接 (防止 stale connection)
3. 如果匹配:
   └─ 日志: "[RPC] sdk-daemon is ready"
   └─ 调用 OnReady() 回调
   └─ server.connected = true
4. 如果不匹配:
   └─ 日志: "[RPC] dropping stale EventReady from replaced connection"
5. connMu.Unlock()
```

### RPCServer.SendRequestAndWait @ 0x89a880

```
1. nextRequestID() → req-{counter}
2. 构建 Message { Type: "request", Method: method, ID: reqID, Params: params }
3. responseCh = make(chan *Message, 1) — 带缓冲 1
4. pendingMu.Lock()
5. pendingReqs[reqID] = pendingRequest { responseCh }
6. pendingMu.Unlock()
7. defer: pendingMu.Lock(); delete(pendingReqs, reqID); pendingMu.Unlock()
8. JSON Marshal(message)
9. writeFrame(conn, json) — 发送
10. timer = time.NewTimer(timeout)
11. select:
    ├─ case <-stopCh: return error("server stopped")
    ├─ case <-timer.C: return error("request timed out after %v")
    └─ case resp := <-responseCh:
        ├─ 如果 resp.Error: return error("RPC error %d: %s")
        └─ 否则: return resp
```

### RPCServer.handleResponse @ 0x898f00

```
1. 从 pendingReqs 中查找 response.ID
2. 如果找到:
   └─ pendingReq.responseCh <- response — 传递给等待的 SendRequestAndWait
3. 如果未找到:
   └─ 日志: "[RPC] Received response for unknown request: id=%s"
```

### RPCServer.SendNotification @ 0x89b040

```
1. 构建 Message { Type: "event", Method: method, Params: params }
2. JSON Marshal
3. writeFrame(conn, json) — 发送，不等待响应
```

### RPCServer.SendGuestResponse @ 0x898d40

```
1. 构建 Message { Type: "response", ID: id, ID2: id2, Result: result, Error: error }
2. JSON Marshal
3. writeFrame(conn, json)
```

### RPCServer.writeFrame @ 0x89a640

```
1. WriteMessage(conn, json)
```

### RPCServer.IsConnected @ 0x897e00

```
connMu.RLock()
connected = server.connected
connMu.RUnlock()
return connected
```

### RPC Message 结构 (从逆向推断)

```go
type Message struct {
    Type    string      // "request", "response", "event"
    Method  string      // 请求方法名 (仅 request/event)
    ID      string      // 请求 ID (request/response 配对)
    ID2     string      // 第二个 ID (response)
    Params  interface{} // 请求/事件参数
    Result  interface{} // 响应结果
    Error   *RPCError   // 错误 (仅 response)
}

type RPCError struct {
    Code    int
    Message string
}
```

---

## 18. InitHCN — HCN API 初始化

**入口**: `InitHCN` @ 0x8821c0

### 流程
```
1. LazyDLL { Name: "computenetwork.dll", System: true }
2. 解析 9 个函数指针:
   ├─ HcnCreateNetwork (20 chars)
   ├─ HcnDeleteNetwork (16 chars)
   ├─ HcnOpenNetwork (14 chars)
   ├─ HcnCloseNetwork (15 chars)
   ├─ HcnQueryNetworkProperties (25 chars)
   ├─ HcnCreateEndpoint (17 chars)
   ├─ HcnCloseEndpoint (16 chars)
   ├─ HcnQueryEndpointProperties (26 chars)
   └─ (还有一个 20 char 的，可能是 HcnModifyEndpoint)
3. 日志: "[HCN] Initialized HCN API from computenetwork.dll"
```

**完整 HCN API 清单** (从 InitHCN 逆向):
- `HcnCreateNetwork`
- `HcnDeleteNetwork`
- `HcnOpenNetwork`
- `HcnCloseNetwork`
- `HcnQueryNetworkProperties`
- `HcnCreateEndpoint`
- `HcnCloseEndpoint`
- `HcnQueryEndpointProperties`

---

## 19. VirtualNetworkProvider — 网络提供者

**入口**: `VirtualNetworkProvider.Start` @ 0x89c0c0

### 流程
```
1. mu.Lock()
2. 如果 listener 已存在: return error (已启动)
3. NewHVSocketListener(vmId, port=1024) — 创建 vsock listener
4. server.listener = listener
5. context.WithCancel() → cancel
6. server.cancel = cancel
7. wg.Add(1)
8. go acceptLoop() — 启动 accept goroutine
9. 日志: "[VNet] Listening for VM network connections on vsock port 1024"
10. mu.Unlock()
```

**关键发现**: VNet 使用 **vsock port 1024** 作为网络连接端口。

### VirtualNetworkProvider.acceptLoop @ 0x89c580

```
循环:
  1. listener.Accept() — 接受 guest vsock 连接
  2. 日志: "[VNet] VM network connected from %s"
  3. 处理网络流量 (gvisor netstack)
  4. 连接断开:
     └─ 日志: "[VNet] VM network connection ended: %v"
```

### VirtualNetworkProvider.Stop @ 0x89cdc0

```
1. cancel() — 取消 context
2. listener.Close()
3. wg.Wait() — 等待所有 goroutine 结束
```

---

## 20. ConsoleReader — COM 管道读取

**入口**: `ConsoleReader.Start` @ 0x880e60

### 流程
```
1. connectPipe() @ 0x8820c0
   └─ 连接到 named pipe: \\.\pipe\cowork-daemon-console-store
   └─ 日志: "[Console] Connected to daemon console pipe: %s"
2. go readLoop() @ 0x880fa0
   └─ 循环读取 pipe 数据
   └─ 写入日志文件
   └─ 错误时: "[Console] Daemon console read error: %v"
   └─ VM 停止时: "[Console] Stopping console reader (VM no longer running)..."
```

### readLoop @ 0x880fa0

```
循环:
  1. pipe.Read(buffer) — 读取 COM pipe 数据
  2. 如果 EOF 或错误:
     └─ 检查 VM 是否还在运行
     └─ 如果 VM 已停止: break
     └─ 如果 VM 还在运行: 日志错误, continue
  3. 写入日志文件 (带时间戳)
```

**关键发现**: ConsoleReader 连接到一个**独立的 named pipe** (`cowork-daemon-console-store`)，不是 COM1/COM2。这个 pipe 是 guest daemon 的控制台输出通道。
