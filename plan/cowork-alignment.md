# Plan: Sandbox API 对齐 Cowork

## Context

cowork-svc.exe 和 tokimo-sandbox-svc.exe 底层架构一致 — 都是 host service 通过 init (sdk-daemon / tokimo-sandbox-init) 管理 VM 内进程。但 host 侧 API 差异大：

- **cowork**: `subscribe` + `writeStdin` + `isProcessRunning` — 极简，进程管理在 VM 内部
- **sandbox**: `exec` + `spawn` + `subscribe` + `writeStdin` + `kill` + `isProcessRunning` — 复杂，进程管理暴露到 host

目标：砍掉 host 侧多余的 API，对齐 cowork 的极简模型。

## Cowork 逆向结论 (IDA Pro)

### 通信协议
- Host ↔ VM: JSON 消息 over HVSocket (port 51234)
- 消息类型: `notification` (单向), `request` (需回复), `response` (回复), `event` (VM→host 事件)

### Host 侧只有 3 个操作
| 操作 | 实现 | 发送的消息 |
|---|---|---|
| `WriteStdin(id, data)` | `SendNotification("stdin", StdinParams{ID, Data})` | notification |
| `IsProcessRunning(id)` | `SendRequestAndWait("isRunning", IsRunningParams{ID, Timeout})` | request → response |
| `subscribe` | 专用连接，持续接收 event 帧 | 接收 event |

### VM 侧 (sdk-daemon) 管理进程
- init 接收 `stdin` notification → 写入对应进程的 stdin pipe
- init 读取进程 stdout/stderr → 发送 `stdout`/`stderr` event (带 ID)
- 进程退出 → 发送 `exit` event (ID, Code, Signal)
- 进程出错 → 发送 `error` event (ID, Message, Fatal)
- 没有 spawn/kill RPC — 进程生命周期由 init 内部管理

### Event 结构
```
stdout:  { ID: string, Data: string }
stderr:  { ID: string, Data: string }
exit:    { ID: string, Code: *int, Signal: *string }
error:   { ID: string, Message: string, Fatal: bool }
ready:   {}  (init 就绪)
networkStatus:    { Status: string }
apiReachability:  { Status: string }
```

## Sandbox 现状

### 已经对齐的部分
- `start_vm()` 三个平台都自动 OpenShell (Linux: /bin/bash, macOS: /bin/sh, Windows: service 内部)
- `subscribe()` 三平台都有事件泵，能接收 stdout/stderr/exit
- `writeStdin(id, data)` 三平台都实现
- `isProcessRunning(id)` 三平台都实现
- init 协议支持 18 个 Op，事件模型和 cowork 一致

### 需要砍掉的 API
| API | 原因 |
|---|---|
| `exec()` | cowork 没有。调用方应通过 writeStdin 写命令到 shell |
| `spawn()` | cowork 没有。进程由 VM init 内部管理 |
| `kill()` | cowork 没有。信号通过 writeStdin 发送 (如 `\x03` = Ctrl+C) |

### 需要新增的 API
| API | 原因 |
|---|---|
| `shell_id() -> JobId` | 返回 start_vm() 自动创建的 shell 的 JobId，调用方用它来 writeStdin |

## 改动计划

### Phase 1: 新增 `shell_id()` API

**文件**: `src/backend.rs`, `src/api.rs`

```rust
// backend.rs - SandboxBackend trait
fn shell_id(&self) -> Result<JobId>;

// api.rs - Sandbox
pub fn shell_id(&self) -> Result<JobId> {
    self.inner.shell_id()
}
```

三平台实现:
- **Linux** (`src/linux/sandbox.rs`): 返回 `start_vm()` 中 `open_shell` 保存的 shell_child_id 对应的 JobId
- **macOS** (`src/macos/sandbox.rs`): 同上
- **Windows** (`src/windows/sandbox.rs`): 发 `shellId` RPC → service 返回 shell 的 child_id

### Phase 2: 删除 `exec()` API

**文件**: `src/backend.rs`, `src/api.rs`, `src/linux/sandbox.rs`, `src/macos/sandbox.rs`, `src/windows/sandbox.rs`

- 从 `SandboxBackend` trait 删除 `fn exec()`
- 从 `Sandbox` 删除 `pub fn exec()`
- 从三平台 backend 删除 `exec()` 实现
- 删除 `ExecResult` 类型（或标记 deprecated，如果还有其他用途）
- Windows service 侧的 `handle_exec` 保留（不删 service 代码，只改 library API）

### Phase 3: 删除 `spawn()` API

**文件**: `src/backend.rs`, `src/api.rs`, `src/linux/sandbox.rs`, `src/macos/sandbox.rs`, `src/windows/sandbox.rs`

- 从 `SandboxBackend` trait 删除 `fn spawn()`
- 从 `Sandbox` 删除 `pub fn spawn()`
- 从三平台 backend 删除 `spawn()` 实现
- Linux: 清理 `JobSpawnInfo`, `child_to_job` 等 spawn 相关状态（如果不再需要）
- Windows service 侧的 `handle_spawn` 保留

### Phase 4: 删除 `kill()` API

**文件**: `src/backend.rs`, `src/api.rs`, `src/linux/sandbox.rs`, `src/macos/sandbox.rs`, `src/windows/sandbox.rs`

- 从 `SandboxBackend` trait 删除 `fn kill()`
- 从 `Sandbox` 删除 `pub fn kill()`
- 从三平台 backend 删除 `kill()` 实现
- 信号发送改为: `sandbox.write_stdin(&shell_id, &[0x03])` (Ctrl+C = SIGINT)
- Windows service 侧的 `handle_kill` 保留

### Phase 5: 清理 svc_protocol (Windows)

**文件**: `src/svc_protocol.rs`

- 删除 `method::EXEC`, `method::SPAWN`, `method::KILL` 常量（如果 library 不再使用）
- 删除 `ExecParams`, `SpawnResult`, `KillParams` 类型（如果 library 不再使用）
- 保留 `method::WRITE_STDIN`, `method::SUBSCRIBE`, `method::IS_PROCESS_RUNNING`
- 新增 `method::SHELL_ID`

### Phase 6: 更新文档

**文件**: `CLAUDE.md`, `src/api.rs` doc comments

- 更新 Public API 文档，反映新的极简 API
- 更新示例代码
- 记录信号发送方式 (writeStdin + bytes)

## 调用方迁移指南

### 之前 (sandbox API)
```rust
let sb = Sandbox::connect()?;
sb.configure(params)?;
sb.start_vm()?;
let r = sb.exec(&["python", "script.py"], ExecOpts::default())?;
println!("{}", r.stdout_str());
sb.stop_vm()?;
```

### 之后 (cowork-aligned API)
```rust
let sb = Sandbox::connect()?;
sb.configure(params)?;
sb.start_vm()?;
let shell = sb.shell_id()?;

// 执行命令
sb.write_stdin(&shell, b"python script.py\n")?;
// stdout/stderr 通过 subscribe() 接收

// 发信号
sb.write_stdin(&shell, &[0x03])?;  // Ctrl+C = SIGINT

sb.stop_vm()?;
```

## 不改的部分

- init 协议 (18 个 Op) — 保持不变，init 的能力不受 host API 影响
- 事件泵 — 三平台都保持现有实现
- Windows service 侧的 handle_exec/handle_spawn/handle_kill — 保留，service 是独立的
- PTY 支持 — 保持不变
- Plan9/mount 相关 API — 保持不变

## 验证

1. `cargo build` 三平台编译通过
2. `cargo test --lib` 单元测试通过
3. 手动测试: start_vm → shell_id → write_stdin("echo hello") → subscribe 收到 stdout
4. 手动测试: write_stdin("\x03") → subscribe 收到 exit event
5. 确认 CLAUDE.md 示例代码可运行
