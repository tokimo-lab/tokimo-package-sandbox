# Tokimo Windows Sandbox — 架构 & 接手指南

> Audience: 接手 Windows 后端开发的工程师
> Last verified: 2026-04-30 — 14/14 `tests/session.rs` 用例通过
> Last commit: `094e413 windows: align with cowork (HCS+HvSocket) ...`

---

## 1. 一图全景

```
┌────────────────────────────────────────────────────────────────────┐
│ 用户进程 (e.g. cargo test session_exec_echo)                       │
│   tokimo_package_sandbox::Session::open()                          │
│       │                                                            │
│       ▼  Named Pipe  \\.\pipe\tokimo-sandbox-svc                   │
│       │  (length-prefixed JSON, FILE_FLAG_OVERLAPPED)              │
│       │                                                            │
│       │  ┌─ SvcRequest::OpenSession                                │
│       │  └─ SvcResponse::SessionOpened                             │
│       │     之后管道转为「透明字节隧道」                           │
└───────┼────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────────┐
│ tokimo-sandbox-svc.exe   (LocalSystem 服务，可由 MSIX 注册)        │
│   src/bin/tokimo-sandbox-svc/imp/mod.rs                            │
│                                                                    │
│  ┌──────────────────┐    ┌──────────────────┐                      │
│  │ NamedPipe Server │    │ HvSocket Listener│                      │
│  │ OVERLAPPED I/O   │    │ AF_HYPERV        │                      │
│  │                  │    │ HV_GUID_WILDCARD │                      │
│  └────────┬─────────┘    │ Port 50003       │                      │
│           │              └────────┬─────────┘                      │
│           │  Tunnel Bridge        │                                │
│           │ (两线程 ov_read/      │                                │
│           │  ov_write 双向拷贝)   │                                │
│           └─────────┬─────────────┘                                │
│                     │                                              │
│  ┌──────────────────▼───────────────┐                              │
│  │  HCS API  (ComputeCore.dll)      │                              │
│  │  Schema 2.5 LinuxKernelDirect    │                              │
│  │  imp/hcs.rs  imp/vmconfig.rs     │                              │
│  └──────────────────┬───────────────┘                              │
└─────────────────────┼──────────────────────────────────────────────┘
                      │ Hyper-V micro-VM
                      ▼
┌────────────────────────────────────────────────────────────────────┐
│ Linux Guest                                                        │
│   ├─ Kernel (vmlinuz, 14.3 MB) ── from Claude vm_bundle            │
│   ├─ Initrd (initrd.img, 169 MB) ── from Claude vm_bundle          │
│   │     standard initramfs-tools, mounts /dev/sda → switch_root    │
│   ├─ /dev/sda  = SCSI VHDX rootfs (ext4, ~360 MB)                  │
│   ├─ COM2      = kernel console (named pipe to host, debug only)   │
│   └─ tokimo-sandbox-init  (PID 1, Rust musl static)                │
│         │                                                          │
│         │  AF_VSOCK connect(CID=2 host, port=50003)                │
│         ▼                                                          │
│      length-prefixed JSON (Op/Reply/Event)                         │
│         │                                                          │
│         └─ /bin/bash (用户命令) … 多个孩子                         │
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
| [client.rs](src/windows/client.rs) | 打开 `\\.\pipe\tokimo-sandbox-svc`（FILE_FLAG_OVERLAPPED），发 OpenSession，得到 `OvPipe` |
| [ov_pipe.rs](src/windows/ov_pipe.rs) | ⚠️ **关键**：OVERLAPPED Read/Write 包装。同步管道在同一 instance 上会让 ReadFile 阻塞 WriteFile，必须用这个 |
| [init_client.rs](src/windows/init_client.rs) | 在透明隧道上跑 init 协议（Hello/Spawn/Exec/Kill…）。reader 线程 + Mutex<OvPipe> writer |
| [protocol.rs](src/windows/protocol.rs) | SvcRequest / SvcResponse JSON wire types |
| [session.rs](src/windows/session.rs) | `open_session()`：路径发现 → `client::open_session` → `WinInitClient::new` → `hello()` → `open_shell()` |
| [mod.rs](src/windows/mod.rs) | NetworkPolicy 翻译 + 路径发现（`find_kernel`/`find_initrd`/`find_rootfs_vhdx`） |
| [safe_path.rs](src/windows/safe_path.rs) | TOCTOU 安全的工作区路径 canonicalize |

### 2.2 Service（LocalSystem，常驻）— `src/bin/tokimo-sandbox-svc/`

| 文件 | 作用 |
|---|---|
| [imp/mod.rs](src/bin/tokimo-sandbox-svc/imp/mod.rs) | SCM 生命周期 + 命名管道服务器 + 客户端校验 + `handle_open_session` 主流程 |
| [imp/hcs.rs](src/bin/tokimo-sandbox-svc/imp/hcs.rs) | 动态加载 ComputeCore.dll，封装 create/start/terminate/close/poll |
| [imp/vmconfig.rs](src/bin/tokimo-sandbox-svc/imp/vmconfig.rs) | HCS Schema 2.5 JSON 生成（VHDX SCSI + Plan9 + HvSocketConfig + ComPorts） |
| [imp/hvsock.rs](src/bin/tokimo-sandbox-svc/imp/hvsock.rs) | AF_HYPERV listener：`HV_GUID_WILDCARD` + 端口 50003，等待 guest 拨入 |

`handle_open_session` 关键步骤：

1. 注册表写入 `HKLM\...\GuestCommunicationServices\<port-50003-guid>` (`ElementName` + `SecurityDescriptor "D:(A;;GA;;;WD)"`)
2. **先** bind hvsock listener（以便 VM 一启动 init 就能连）
3. 调用 HCS create + start，启动 VM
4. accept 来自 guest 的 hvsock 连接（最多等 60s）
5. 给客户端回 `SessionOpened`
6. 启动两个隧道线程：`pipe → hvsock`、`hvsock → pipe`，双向拷贝直到任一端断开
7. 任一端断开 → HCS Terminate → CloseHandle

### 2.3 Guest Init（VM 内 PID 1）— `src/bin/tokimo-sandbox-init/`

| 文件 | 作用 |
|---|---|
| [main.rs](src/bin/tokimo-sandbox-init/main.rs) | 解析 `tokimo.*` cmdline；`AF_VSOCK connect(CID=2, port=50003)`；mount /mnt/work via 9p `trans=fd` |
| [server.rs](src/bin/tokimo-sandbox-init/server.rs) | length-prefixed JSON 解码；分发 Op；通过 vsock 把 Reply/Event 推回 host |
| [child.rs](src/bin/tokimo-sandbox-init/child.rs) | 拉起子进程，stdout/stderr → Event::Stdout/Stderr，退出 → Event::Exit |
| [pty.rs](src/bin/tokimo-sandbox-init/pty.rs) | shell 模式 PTY 处理 |

---

## 3. VM 启动用什么文件，从哪里来？

三个文件都从姊妹仓库 [tokimo-lab/tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs/releases) 的 GitHub Release 下载，统一放在本仓库的 `vm/` 目录。**不再读任何环境变量，不再依赖 Claude Desktop。**

```powershell
# 一键下载最新 release 到 vm/
pwsh scripts/fetch-vm.ps1
# 指定 tag
pwsh scripts/fetch-vm.ps1 -Tag v1.6.0
```

完整产出由 sister project 的 `.github/workflows/build.yml` 在 git tag `v*` 上触发。

### 3.1 内核（vmlinuz）

- **来源**：sister CI 从 `debian:13` 容器复制 `linux-image-amd64`（**不是** cloud kernel，含 vsock / hv_sock 可加载模块）
- **位置**：`vm/vmlinuz`

### 3.2 Initrd（initrd.img）

- **来源**：sister CI 现场打包
- **包含**：busybox + Hyper-V 必要模块（hv_vmbus, hv_sock, hv_storvsc, ext4, 9p 等）+ `init.sh`（PID 1）+ `tokimo-sandbox-init`（Rust musl 静态二进制，由 sister CI 跨架构编译塞入）
- **session 模式流程**：init.sh 加载模块 → mount `/dev/sda` → 拷 `tokimo-sandbox-init` 进 rootfs → `chroot` 进去并 exec
- **位置**：`vm/initrd.img`

### 3.3 Rootfs（rootfs.vhdx）

- **来源**：sister CI 从 Debian 13 rootfs → `mkfs.ext4 -d` → `qemu-img convert -O vhdx`
- **包含**：Debian 13 瘦身版、Node.js 24、Python 3.13、LibreOffice headless、ffmpeg 等（详见 sister README）
- **位置**：`vm/rootfs.vhdx`

### 3.4 路径发现

[`src/windows/mod.rs`](src/windows/mod.rs) `find_vm_dir()`：从 service exe 路径向上走父目录，找同时包含 `vmlinuz` + `initrd.img` + `rootfs.vhdx` 三个文件的 `vm/` 目录。**不再读任何环境变量。**

### 3.5 内核命令行（[vmconfig.rs:163](src/bin/tokimo-sandbox-svc/imp/vmconfig.rs#L163)）

Session 模式：

```
console=ttyS1 loglevel=7 root=/dev/sda rootfstype=ext4 rw
tokimo.session=1 tokimo.work_port=50002 tokimo.init_port=50003
```

`tokimo.*` 由我们自己的 init.sh / tokimo-sandbox-init 解析；其余是标准 Linux。

---

## 4. 目前所有「文件」位置一览

### 4.1 二进制 / 运行时

| 路径 | 作用 |
|---|---|
| `<repo>/vm/vmlinuz` | Linux kernel |
| `<repo>/vm/initrd.img` | Initrd |
| `<repo>/vm/rootfs.vhdx` | rootfs |
| `target\debug\tokimo-sandbox-svc.exe` | 服务二进制（dev） |
| `target\release\tokimo-sandbox-svc.exe` | 服务二进制（release） |
| `target\msix\Tokimo.SandboxSvc.msix` | 打包好的 MSIX |
| `\\.\pipe\tokimo-sandbox-svc` | 服务监听管道 |
| `\\.\pipe\tokimo-vm-com2-{vm_id}` | VM 内核 console |
| `C:\tokimo-debug\last-vm-tunnel.log` | 隧道线程时序日志 |
| `C:\tokimo-debug\last-hcs-session-config.json` | 上次 HCS Schema dump |
| `HKLM\...\GuestCommunicationServices\<guid>\` | hvsock 服务注册表项 |

### 4.2 构建脚本

| 路径 | 作用 |
|---|---|
| [scripts/fetch-vm.ps1](scripts/fetch-vm.ps1) | 从 sister project release 下载 VM 产物到 `vm/` |
| [scripts/build-msix.ps1](scripts/build-msix.ps1) | 打包 MSIX |
| [scripts/check-env.ps1](scripts/check-env.ps1) | 接手者第一步：核实 Hyper-V / HCS / 文件齐不齐 |

---

## 5. 通讯链路细节

### 5.1 控制通道（host → svc）

```
client                       service
  │                             │
  │ CreateFileW(pipe,           │
  │   FILE_FLAG_OVERLAPPED) ──▶ │ ConnectNamedPipe (overlapped)
  │                             │
  │ ──── SvcRequest::OpenSession  ──▶
  │                             │ … 启动 VM、bind hvsock、accept guest …
  │ ◀── SvcResponse::SessionOpened
  │                             │
  │ ====== 之后管道变成「透明隧道」 ======
  │                             │
  │ ◀── init Hello reply  (从 guest 经 hvsock → service → pipe)
  │ ──▶ init Spawn op    (反向)
```

### 5.2 数据通道（svc ↔ guest）

- Host: `AF_HYPERV` (family 34) listener，VmId=`HV_GUID_WILDCARD`，ServiceId 由 port 50003 套模板 `XXXXXXXX-FACB-11E6-BD58-64006A7986D3` 生成
- Guest: `AF_VSOCK` connect to `(CID=VMADDR_CID_HOST=2, port=50003)`
- 因为 HCS HvSocketConfig 的 `ServiceTable[guid].AllowWildcardBinds: true`，所以 host 可以用 wildcard VmId bind，VM 启动后无需提前知道 VM 的 GUID

### 5.3 Init wire 协议

`src/protocol/{types.rs, wire.rs}`：4-byte BE 长度前缀 + serde_json `Frame { Op | Reply | Event }`，跨平台共用（Linux/macOS/Windows 都跑同一份 init server）。

---

## 6. ⚠️ 已经踩过的坑（必看）

### 6.1 Windows 同步管道死锁

**症状**：第一次 op 成功，第二次 op 卡死 → ERROR_BROKEN_PIPE。

**原因**：Windows 同步 named pipe 在同一个 pipe instance 上**串行化** ReadFile + WriteFile，**即使来自不同线程、即使通过 DuplicateHandle 拿到不同 HANDLE**。reader 线程的 pending ReadFile 会卡住主线程的 WriteFile。

**修复**：客户端和服务端**两端**的 pipe 都必须 `FILE_FLAG_OVERLAPPED`，所有 I/O 走 OVERLAPPED + event。代码见 [src/windows/ov_pipe.rs](src/windows/ov_pipe.rs)。

### 6.2 HvSocket 必须 ServiceTable + AllowWildcardBinds

只设 `DefaultBindSecurityDescriptor` 不够，guest 连过来会 `ETIMEDOUT`。必须在 HCS Schema 的 `HvSocketConfig.ServiceTable[<port-guid>]` 里写 `BindSecurityDescriptor` + `ConnectSecurityDescriptor` + `AllowWildcardBinds: true`，并且**同时**写 HKLM 注册表项（cowork-svc.exe IDA 反编译实锤）。

### 6.3 Listener 必须先于 VM 启动

VM 一起来 init 就立即 dial 50003。如果 host 还没 bind，guest 会 ECONNREFUSED 然后内部重试 30s，浪费时间。流程顺序固定：bind → start VM → accept。

---

## 7. 接手第一天 checklist

```powershell
# 1) 下载 VM 产物到 vm/
pwsh scripts\fetch-vm.ps1

# 2) 跳环境检查
pwsh scripts\check-env.ps1

# 3) build & 装服务（dev）
cargo build --bin tokimo-sandbox-svc
# 双击或在管理员 pwsh 跑：
target\debug\tokimo-sandbox-svc.exe --console

# 4) 跑测试（不再需要任何 env var）
cargo test --test session -- --test-threads=1 --nocapture
# 期望: 14 passed; 0 failed
```

调试日志看：

- 服务侧：`--console` 自身 stderr + `C:\tokimo-debug\last-vm-tunnel.log`
- 客户端侧：测试 stderr（已经有 `[winclient]` 前缀的 log，可关）
- VM 内核：附加到 `\\.\pipe\tokimo-vm-com2-<vm_id>` 看 dmesg


