# Tokimo Windows Sandbox — 架构 & 接手指南

> Audience: 接手 Windows 后端开发的工程师
> Last verified: 2026-04-30 — 14/14 `tests/session.rs` 用例通过（4 线程并发，16s）
> Artifacts: in-repo `vm-image.yml`, tag prefix `vm-v*` (e.g. `vm-v1.9.0`)

---

## 1. 一图全景

```
┌────────────────────────────────────────────────────────────────────┐
│ 用户进程 (e.g. cargo test session_exec_echo)                       │
│   tokimo_package_sandbox::Session::open()                          │
│       │                                                            │
│       ▼  Named Pipe  \\.\pipe\tokimo-sandbox-svc                   │
│       │  (FILE_FLAG_OVERLAPPED, length-prefixed JSON)              │
│       │                                                            │
│       │  ┌─ SvcRequest::OpenSession                                │
│       │  └─ SvcResponse::SessionOpened                             │
│       │     之后管道转为「透明字节隧道」                           │
└───────┼────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────────┐
│ tokimo-sandbox-svc.exe   (LocalSystem 服务)                        │
│   src/bin/tokimo-sandbox-svc/imp/mod.rs                            │
│                                                                    │
│  ┌──────────────────┐    ┌──────────────────────────────┐          │
│  │ NamedPipe Server │    │ HvSocket Listener            │          │
│  │ OVERLAPPED I/O   │    │ AF_HYPERV                    │          │
│  │ PIPE_TYPE_MESSAGE│    │ VmId = HV_GUID_WILDCARD      │          │
│  └────────┬─────────┘    │ ServiceId = per-session GUID │          │
│           │              └────────┬─────────────────────┘          │
│           │  Tunnel Bridge        │                                │
│           │ (两线程双向拷贝)      │                                │
│           └─────────┬─────────────┘                                │
│                     │                                              │
│  ┌──────────────────▼───────────────┐                              │
│  │  HCS API  (ComputeCore.dll)      │                              │
│  │  Schema 2.x LinuxKernelDirect    │                              │
│  │  imp/hcs.rs  imp/vmconfig.rs     │                              │
│  └──────────────────┬───────────────┘                              │
└─────────────────────┼──────────────────────────────────────────────┘
                      │ Hyper-V micro-VM (per-session)
                      ▼
┌────────────────────────────────────────────────────────────────────┐
│ Linux Guest                                                        │
│   ├─ Kernel (vmlinuz) ── from in-repo vm-v* release                │
│   ├─ Initrd (initrd.img) ── busybox + hv_vmbus/hv_sock 模块等     │
│   ├─ /dev/sda  = per-session VHDX clone (ext4, ~360 MB)           │
│   ├─ COM2      = kernel console → C:\tokimo-debug\last-vm-com2.log │
│   └─ tokimo-sandbox-init  (PID 1, Rust musl static)                │
│         │                                                          │
│         │  AF_VSOCK connect(CID=VMADDR_CID_HOST=2,                │
│         │                   port=<per-session>)                    │
│         ▼                                                          │
│      length-prefixed JSON (Op/Reply/Event)                         │
│         │                                                          │
│         └─ /bin/bash + 用户命令 (支持多个并发 job)                 │
│                                                                    │
│   /mnt/work  = Plan9-over-vsock share "work"  (port 50002)         │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. 三类组件

### 2.1 Library（用户进程内）— `src/windows/`

| 文件 | 作用 |
|---|---|
| [mod.rs](src/windows/mod.rs) | NetworkPolicy 翻译 + VM 文件路径发现（`find_vm_dir`） |
| [session.rs](src/windows/session.rs) | `Session::open()`：路径发现 → `client::open_session` → `WinInitClient::new` → `hello()` → `open_shell()` |
| [client.rs](src/windows/client.rs) | 打开 `\\.\pipe\tokimo-sandbox-svc`（`FILE_FLAG_OVERLAPPED`），发 OpenSession，得到 `OvPipe` |
| [ov_pipe.rs](src/windows/ov_pipe.rs) | ⚠️ **关键**：OVERLAPPED Read/Write 包装。Windows 同步管道在同一 instance 上串行化 ReadFile+WriteFile（即使跨线程），必须用 OVERLAPPED |
| [init_client.rs](src/windows/init_client.rs) | 在透明隧道上跑 init 控制协议（Hello/Spawn/Exec/Kill/Event…）；reader 线程 + Mutex<OvPipe> writer |
| [protocol.rs](src/windows/protocol.rs) | `SvcRequest` / `SvcResponse` JSON wire types（length-prefixed framing）|
| [safe_path.rs](src/windows/safe_path.rs) | TOCTOU 安全的工作区路径 canonicalize — 拒绝 symlink/junction/hardlink |

### 2.2 Service（LocalSystem，常驻）— `src/bin/tokimo-sandbox-svc/imp/`

| 文件 | 作用 |
|---|---|
| [mod.rs](src/bin/tokimo-sandbox-svc/imp/mod.rs) | SCM 生命周期 + 命名管道服务器 + 客户端 Authenticode 校验 + `handle_open_session` 主流程 |
| [hcs.rs](src/bin/tokimo-sandbox-svc/imp/hcs.rs) | 动态加载 ComputeCore.dll，封装 create/start/terminate/close/poll |
| [vmconfig.rs](src/bin/tokimo-sandbox-svc/imp/vmconfig.rs) | HCS Schema 2.x JSON 生成（SCSI VHDX + Plan9 + HvSocketConfig + ComPorts）；`alloc_session_init_port()` |
| [hvsock.rs](src/bin/tokimo-sandbox-svc/imp/hvsock.rs) | AF_HYPERV listener：`HV_GUID_WILDCARD` VmId + per-session ServiceId，等待 guest 拨入 |

`handle_open_session` 关键步骤（每个 Session 独立）：

1. 调用 `vmconfig::alloc_session_init_port()` 分配本 session 专属 vsock 端口（`0x40000000 | counter`）
2. 将对应 GUID 写入 `HKLM\...\GuestCommunicationServices\<guid>`（`ElementName` + `SecurityDescriptor "D:(A;;GA;;;WD)"`）
3. 克隆 `rootfs.vhdx` 为 per-session 副本（隔离并发会话的文件系统）
4. **先** bind HvSocket listener（`VmId=HV_GUID_WILDCARD`, `ServiceId=per-session`），以便 VM 一启动 init 就能立即连
5. 调用 HCS create + start，启动 VM
6. accept 来自 guest 的 hvsock 连接（最多等 60s）
7. 给客户端回 `SvcResponse::SessionOpened`
8. 启动两个隧道线程：`pipe → hvsock`（写 guest）、`hvsock → pipe`（读 guest），双向拷贝直到任一端断开
9. 任一端断开 → HCS Terminate → CloseHandle → 清理 session VHDX 副本

### 2.3 Guest Init（VM 内 PID 1）— `src/bin/tokimo-sandbox-init/`

| 文件 | 作用 |
|---|---|
| [main.rs](src/bin/tokimo-sandbox-init/main.rs) | 解析 `tokimo.*` cmdline 参数；`AF_VSOCK connect(CID=2, port=<tokimo.init_port>)`；mount /mnt/work via 9p `trans=fd` |
| [server.rs](src/bin/tokimo-sandbox-init/server.rs) | length-prefixed JSON 解码；分发 Op；通过 vsock 把 Reply/Event 推回 host |
| [child.rs](src/bin/tokimo-sandbox-init/child.rs) | 拉起子进程，stdout/stderr → Event::Stdout/Stderr，退出 → Event::Exit |
| [pty.rs](src/bin/tokimo-sandbox-init/pty.rs) | shell 模式 PTY 处理 |

---

## 3. VM 启动用什么文件，从哪里来？

三个文件都从本仓库 `vm-image.yml` 工作流发布的 GitHub Release（tag 前缀 `vm-v*`）下载，统一放在本仓库的 `vm/` 目录。构建过程见 [`packaging/vm-base/README.md`](../packaging/vm-base/README.md)。

```powershell
# 下载最新 release 到 vm/
pwsh scripts\windows\fetch-vm.ps1
# 指定 tag
pwsh scripts\windows\fetch-vm.ps1 -Tag vm-v1.9.0
```

### 3.1 内核（vmlinuz）

- **来源**：`vm-base.yml` 在 `debian:13` 容器中复制 `linux-image-{amd64,arm64}`（含 hv_vmbus / hv_sock 等可加载模块）
- **大小**：约 15 MB（含模块）
- **位置**：`vm/vmlinuz`

### 3.2 Initrd（initrd.img）

- **来源**：`vm-base.yml` 现场打包基础 initrd（busybox + Hyper-V 必要模块：hv_vmbus, hv_sock, hv_storvsc, ext4, 9p 等共 ~19 个 .ko，外加 `init.sh` 挂载/chroot 流程）；`vm-image.yml` 在此之上调用 `rebake-initrd.sh`，把当次构建的 `tokimo-sandbox-init` 注入 `/bin/`
- **session 模式流程**：init.sh 加载模块 → mount `/dev/sda` → chroot → exec `tokimo-sandbox-init`
- **位置**：`vm/initrd.img`

> ⚠️ v1.7.0 发布的 initrd 的 `modules/` 目录为空（build.sh 的 `find -delete` 在模块依赖解析之前运行）——会导致 `hv_vmbus: missing` 错误、hvsock accept 超时。v1.7.1 已修复，请务必使用 v1.7.1+。

### 3.3 Rootfs（rootfs.vhdx）

- **来源**：`vm-base.yml` 从 Debian 13 rootfs → `mkfs.ext4 -d` → `qemu-img convert -O vhdx`
- **包含**：Debian 13 瘦身版、Node.js 24、Python 3.13、LibreOffice headless、ffmpeg 等
- **位置**：`vm/rootfs.vhdx`（被服务按 session 克隆为独立副本，互不影响）

### 3.4 路径发现

[`src/windows/mod.rs`](src/windows/mod.rs) `find_vm_dir()`：从 service exe 路径向上走父目录，找同时包含 `vmlinuz` + `initrd.img` + `rootfs.vhdx` 三个文件的 `vm/` 目录。**不读任何环境变量。**

### 3.5 内核命令行（[vmconfig.rs](src/bin/tokimo-sandbox-svc/imp/vmconfig.rs)）

Session 模式：

```
console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw
tokimo.session=1 tokimo.work_port=50002 tokimo.init_port=<per-session-port>
```

`tokimo.init_port` 是本 session 专属的 vsock 端口（由 `alloc_session_init_port()` 分配），guest init 以此端口连回 host。

---

## 4. 目前所有「文件」位置一览

### 4.1 二进制 / 运行时

| 路径 | 作用 |
|---|---|
| `<repo>/vm/vmlinuz` | Linux kernel |
| `<repo>/vm/initrd.img` | Initrd |
| `<repo>/vm/rootfs.vhdx` | rootfs（只读源；每 session 克隆一份）|
| `target\debug\tokimo-sandbox-svc.exe` | 服务二进制（dev） |
| `target\release\tokimo-sandbox-svc.exe` | 服务二进制（release） |
| `target\msix\Tokimo.SandboxSvc.msix` | 打包好的 MSIX |
| `\\.\pipe\tokimo-sandbox-svc` | 服务监听管道 |
| `\\.\pipe\tokimo-vm-com2-{vm_id}` | VM 内核 console（调试） |
| `C:\tokimo-debug\last-vm-com2.log` | 最后一次 VM 的内核 kmsg |
| `C:\tokimo-debug\last-hcs-session-config.json` | 最后一次 HCS Schema dump |
| `HKLM\SYSTEM\CurrentControlSet\Services\HvHostSvc\Parameters\GuestCommunicationServices\<guid>\` | 每 session 注册的 hvsock 服务 |

### 4.2 构建脚本

| 路径 | 作用 |
|---|---|
| [scripts/windows/fetch-vm.ps1](scripts/windows/fetch-vm.ps1) | 从 sister project release 下载 VM 产物到 `vm/` |
| [scripts/windows/build-msix.ps1](scripts/windows/build-msix.ps1) | 打包 MSIX |
| [scripts/check-env.ps1](scripts/check-env.ps1) | 接手者第一步：核实 Hyper-V / HCS / 文件齐不齐 |

---

## 5. 通讯链路细节

### 5.1 控制通道（host ↔ svc，named pipe）

```
client (library)                 service
  │                                  │
  │ CreateFileW(pipe,                │
  │   FILE_FLAG_OVERLAPPED) ──────▶  │ ConnectNamedPipe (overlapped)
  │                                  │
  │ ──── SvcRequest::OpenSession ──▶ │
  │                                  │ … 分配端口、注册 GUID、克隆 VHDX、
  │                                  │   bind hvsock、启动 VM、accept guest …
  │ ◀── SvcResponse::SessionOpened ──│
  │                                  │
  │ ══════ 管道之后变为「透明隧道」 ══════
  │                                  │
  │ ◀── init Hello reply  (guest → hvsock → svc tunnel → pipe)
  │ ──▶ init Spawn op    (反向)
```

### 5.2 数据通道（svc ↔ guest，AF_HYPERV）

- **Host**：`AF_HYPERV` (family 34)，`VmId = HV_GUID_WILDCARD`，`ServiceId = per-session GUID`（`{port:08X}-FACB-11E6-BD58-64006A7986D3`）
- **Guest**：`AF_VSOCK connect(CID=VMADDR_CID_HOST=2, port=<tokimo.init_port>)`
- `HvSocketConfig.ServiceTable[guid].AllowWildcardBinds = true` 使 host wildcard 监听器可以接收来自任意 VM 的连接

> ⚠️ **并发约束**：Hyper-V 父分区监听器必须用 `HV_GUID_WILDCARD`；绑定具体子 VM 的 RuntimeId → `WSAEACCES (10013)`。两个 wildcard 监听器用同一 ServiceId → `WSAEADDRINUSE (10048)`。因此**并发 session 必须每 session 使用不同 ServiceId**。

### 5.3 Init wire 协议

`src/protocol/{types.rs, wire.rs}`：4-byte BE 长度前缀 + serde_json `Frame { Op | Reply | Event }`，跨平台共用。

---

## 6. ⚠️ 已经踩过的坑（必看）

### 6.1 Windows 同步管道死锁

**症状**：第一次 op 成功，第二次 op 卡死 → ERROR_BROKEN_PIPE。

**原因**：Windows 同步 named pipe 在同一个 pipe instance 上**串行化** ReadFile + WriteFile，即使来自不同线程。reader 线程的 pending ReadFile 会卡住主线程的 WriteFile。

**修复**：客户端和服务端两端的 pipe 都必须 `FILE_FLAG_OVERLAPPED`，所有 I/O 走 OVERLAPPED + event。代码见 [src/windows/ov_pipe.rs](src/windows/ov_pipe.rs)。

### 6.2 HvSocket 必须 ServiceTable + AllowWildcardBinds

只设 `DefaultBindSecurityDescriptor` 不够，guest 连过来会 `ETIMEDOUT`。必须在 HCS Schema 的 `HvSocketConfig.ServiceTable[<port-guid>]` 里写 `BindSecurityDescriptor` + `ConnectSecurityDescriptor` + `AllowWildcardBinds: true`，并且**同时**写 HKLM 注册表项（HvHostSvc GuestCommunicationServices）。

### 6.3 Listener 必须先于 VM 启动

VM 一起来 init 就立即 dial vsock 端口。如果 host 还没 bind，guest 会 ECONNREFUSED 后内部重试 30s，浪费时间。流程顺序固定：**bind → start VM → accept**。

### 6.4 HvSocket 并发 session 不能共用 ServiceId

**症状（旧实现）**：并发跑多个 session 时，第一个 listener 绑定了 ServiceId；第二个绑同一 ServiceId → `WSAEADDRINUSE (10048)`，session 失败。

**根因**：父分区监听器必须用 `HV_GUID_WILDCARD` VmId，而 wildcard 监听器的 `(VmId, ServiceId)` 不区分 VM，只要 ServiceId 相同就冲突。`bind(specific-child-RuntimeId)` 试图规避但会 `WSAEACCES (10013)` — 父分区**没有权限**绑定子 VM 的 RuntimeId。

**修复**：`alloc_session_init_port()` 每次返回递增端口（`0x40000000 | counter`），每个 session 有唯一 ServiceId。对应 GUID 在 HKLM 注册、在 HCS Schema 的 ServiceTable 中声明、通过 `tokimo.init_port` 内核参数传给 guest。

### 6.5 initrd 模块为空（rootfs v1.7.0 bug）

`build.sh` 的 `find /lib/modules -name '*.ko' -delete` 在模块依赖解析之前运行，导致 initrd 的 `modules/` 目录为空。症状：`hv_vmbus: missing module`，hvsock 永不建立，accept 60s 超时。**v1.7.1 已修复**，使用 `pkg fetch-vm` 时请确认 tag ≥ v1.7.1。

### 6.6 `--install` 报 "IO error in winapi call"

`windows-service 0.8.0` 的 `Error::Winapi(io::Error)` 的 `Display` 实现写死了那个字符串，不打印底层 OS 码。我们已在 `install_service()` 中用 `Error::source().downcast_ref::<io::Error>().raw_os_error()` 提取真实码，并格式化为 `<msg> (os error N)` 输出。

### 6.7 两个服务名

| 常量 | 值 | 用途 |
|---|---|---|
| `SERVICE_NAME` | `TokimoSandboxSvc` | MSIX 部署（`AppxManifest.xml`），SCM dispatcher 注册名 |
| `INSTALL_SERVICE_NAME` | `tokimo-sandbox-svc` | CLI `--install` 注册名，与 MSIX 不冲突 |

若同一台机器同时安装了 MSIX 包和 CLI install，两套服务共用同一管道 `\\.\pipe\tokimo-sandbox-svc`；任意一个 Running 都可以接受连接。若尝试用 `--install` 时 MSIX 已安装（两者 `SERVICE_DISPLAY` 相同），会收到 `ERROR_DUPLICATE_SERVICE_NAME (1078)` 及清晰的提示，指引先卸载 MSIX。

---

## 7. 接手第一天 checklist

### 7.1 环境准备

```powershell
# 1) 启用 Hyper-V（如未启用）
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
# 或在「Windows 功能」中勾选「虚拟机平台」→ 重启

# 2) 检查环境
pwsh scripts\check-env.ps1

# 3) 下载 VM 产物（需 v1.7.1+）
pwsh scripts\fetch-vm.ps1
```

### 7.2 开发模式（console）

```powershell
# 构建
cargo build --bin tokimo-sandbox-svc

# 以管理员 PowerShell 启动（前台，Ctrl+C 停止）
.\target\debug\tokimo-sandbox-svc.exe --console
```

另开一个普通 PowerShell 运行测试：

```powershell
# 并发跑全部 14 个 session 集成测试
cargo test --test session -- --test-threads=4

# 期望: test result: ok. 14 passed; 0 failed; ... finished in ~16s
```

> **注意**：cargo 在测试前会重新链接二进制；如果服务正在 `--console` 运行，`cargo test` 会失败（`Access is denied`，服务占着 exe）。解决方案：先 `Ctrl+C` 停服务 → `cargo build` → 重启服务 → 用预编译好的 `target\debug\deps\session-*.exe` 直接跑测试。

### 7.3 服务模式（SCM）

```powershell
# 安装（管理员，一次性；注册为 tokimo-sandbox-svc，AutoStart，LocalSystem）
.\target\debug\tokimo-sandbox-svc.exe --install

# 验证状态
Get-Service tokimo-sandbox-svc   # 应该 Running

# 跑测试
.\target\debug\deps\session-*.exe --test-threads=4   # 无需 cargo，避免重编译冲突

# 停止 / 卸载
.\target\debug\tokimo-sandbox-svc.exe --uninstall
```

> 若安装时提示 `(os error 1078)`，说明 MSIX 包已装（服务显示名冲突）：
> ```powershell
> Get-AppxPackage Tokimo.SandboxSvc | Remove-AppxPackage
> ```

### 7.4 调试日志

| 来源 | 路径 / 命令 |
|---|---|
| 服务侧实时日志 | `--console` 模式的 stderr |
| VM 内核 kmsg | `Get-Content C:\tokimo-debug\last-vm-com2.log` |
| HCS Schema dump | `Get-Content C:\tokimo-debug\last-hcs-session-config.json` |
| 管道连接日志 | `[svc]` 前缀打印在服务 stderr |

### 7.5 MSIX 打包发布

```powershell
# 打包（不签名）
pwsh scripts\build-msix.ps1

# 打包 + Authenticode 签名（需证书）
pwsh scripts\build-msix.ps1 -Sign -Thumbprint <cert-thumbprint>
```

产出：`target\msix\Tokimo.SandboxSvc.msix`

---

## 8. 测试用例一览（`tests/session.rs`）

| 测试名 | 验证内容 |
|---|---|
| `session_exec_echo` | 基本 exec，stdout 回路 |
| `session_exec_env_persistence` | 跨 exec env var 保持 |
| `session_exec_cwd_persistence` | 跨 exec cwd 保持 |
| `session_exec_stderr_capture` | stderr 捕获 |
| `session_exec_exit_code_nonzero` | 非零 exit code 透传 |
| `session_exec_large_output` | 大输出（~1 MB）不截断 |
| `session_exec_timeout_tears_down_session` | exec 超时 → session 整体拆除 |
| `session_spawn_captures_output` | spawn job stdout/stderr 捕获 |
| `session_spawn_inherits_cwd` | spawn job 继承 exec 设置的 cwd |
| `session_spawn_timeout_kills_job` | spawn job 超时 → kill job，session 存活 |
| `session_kill_job_keeps_session_alive` | 手动 kill job，session 保持可用 |
| `session_spawn_concurrent_no_crosstalk` | 同一 session 内并发 job，输出无串扰 |
| `session_close_cleans_up` | close() 后连接断开，VM 清理 |
| `session_spawn_exec_mixed` | exec + spawn 混合顺序 |


