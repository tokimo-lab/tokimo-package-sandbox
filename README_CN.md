# tokimo-package-sandbox

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

跨平台原生沙箱库 —— 在隔离环境中运行不受信任的命令。一套 API，三个平台，每个平台使用操作系统原生的隔离原语。

| 平台 | 隔离引擎 | 需要 root | 冷启动 |
|---|---|---|---|
| **Linux** | bubblewrap（用户命名空间）+ smoltcp 用户态网络栈 | 不需要 | ~50 ms |
| **macOS** | Apple Virtualization.framework → Linux 微型虚拟机 + smoltcp 用户态网络栈 | 不需要 | ~2 s |
| **Windows** | Hyper-V HCS → Linux 微型虚拟机 + smoltcp 用户态网络栈（SYSTEM 服务） | 一次性服务安装 | ~600 ms |

三个后端提供完全相同的 `Sandbox` 接口：configure → create → start → spawn shells → stop。同一个 init 二进制（`tokimo-sandbox-init`）在每个沙箱中以 PID 1 运行，使用相同的线路协议，不区分传输层。网络完全统一：三个平台的 `AllowAll` 策略均使用同一套 smoltcp 用户态网络栈。

## 为什么做这个项目

现有的沙箱方案要么是平台专属的（bwrap、jail、WSL），要么需要守护进程和镜像（Docker、Podman）。没有一个开源库能让你用**一套 Rust API** 在 Linux、macOS 和 Windows 上沙箱化一条命令——还要有可用的网络、PTY 支持和动态宿主↔客机文件共享——而不需要 root、Docker 或预构建的容器镜像。

这个项目填补了这个空白。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                      你的应用程序                             │
│                                                             │
│   let sb = Sandbox::connect().unwrap();                     │
│   sb.configure(params).unwrap();                            │
│   sb.start_vm().unwrap();                                   │
│   let r = sb.exec(&["uname", "-a"], ExecOpts::default());   │
│   sb.stop_vm().unwrap();                                    │
└────────────────────────┬────────────────────────────────────┘
                         │  三个平台完全相同的 API
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   LinuxBackend     MacosBackend    WindowsBackend
   （进程内）        （进程内）       （命名管道 RPC）
        │                │                │
        ▼                ▼                ▼
   bwrap + 用户      arcbox-vz →     tokimo-sandbox-svc
   命名空间          VZVirtualMachine   （SYSTEM 服务）
        │                │                │
        └────────┬───────┘                │
                 ▼                        ▼
        tokimo-sandbox-init       Hyper-V HCS 计算系统
        （PID 1，共享二进制）              │
                 │                       │
                 ▼                       ▼
          Linux 客机              Linux 微型虚拟机
```

### Linux — bubblewrap + smoltcp，无虚拟机

```
Sandbox::start_vm()
  │
  ├─ socketpair(AF_UNIX, SOCK_SEQPACKET)     ← init 控制通道
  ├─ socketpair(AF_UNIX, SOCK_STREAM)         ← 网络栈（仅 AllowAll）
  │
  └─ exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts
                 --unshare-net                ← 始终：全新网络命名空间
                 --ro-bind <vm/rootfs>/{usr,bin,sbin,lib,lib64}
                 --ro-bind <vm/rootfs>/etc/{passwd,group}     ← 打包的用户表
                 --ro-bind /etc/{resolv.conf,hosts,ssl,...}   ← 仅宿主网络/CA
                 --cap-add CAP_SYS_ADMIN      ← fusermount3 需要
                 --cap-add CAP_NET_ADMIN      ← 用于 TAP 和 lo 启动
                 --cap-add CAP_NET_RAW        ← 客机 ping 需要
                 --cap-add CAP_MKNOD          ← 回退 TUN 节点创建
                 --dev-bind-try /dev/net/tun  ← 仅 AllowAll
                 -- /path/to/tokimo-sandbox-init bwrap
                        --control-fd=<ctrl>
                        --net-fd=<net>        ← 仅 AllowAll
                        --bringup-lo --mount-sysfs
                              │
                              └─ bwrap 内 PID 2（bwrap 是 PID 1）
                                 ├─ 控制：SEQPACKET，PTY 通过 SCM_RIGHTS 传递
                                 ├─ 网络：STREAM，TAP tk0 ↔ 宿主 smoltcp
                                 └─ FUSE：每个挂载一个 socketpair，宿主 FuseHost 服务
```

- **无守护进程、无服务、不需要 root。** 每个 `Sandbox` 拥有独立的 bwrap+init 组合。
- **打包 rootfs。** `/usr /bin /sbin /lib /lib64 /etc/passwd /etc/group` 都来自 `vm/rootfs/`（与 macOS、Windows 启动用的同一份 artifact），保证三平台 sandbox 内看到同一套工具版本。仅网络/DNS/CA 配置仍从宿主机绑定。
- **网络：** `AllowAll` 和 `Blocked` 都使用 `--unshare-net` 创建全新网络命名空间。`AllowAll` 通过 TAP 设备（`tk0`）叠加 smoltcp 用户态网络栈，经 STREAM socketpair 桥接到宿主——与 macOS 和 Windows 架构完全一致。`Blocked` 只有 `lo`。
- **文件共享：** 所有挂载使用 **FUSE-over-socketpair** —— 与 macOS 和 Windows 共同一套 `FuseHost` + `tokimo-sandbox-fuse` 基础设施。每个挂载获得一个 `AF_UNIX SOCK_STREAM` socketpair；宿主端由 `FuseHost` 服务，客机端通过 `--transport unix-fd` 传递给 `tokimo-sandbox-fuse`。启动时和运行时挂载使用相同机制。
- **PTY：** 主 fd 通过 `SCM_RIGHTS` 传递到宿主，直接 I/O。

### macOS — Virtualization.framework

```
Sandbox::start_vm()
  │
  └─ arcbox-vz → VZVirtualMachine
       ├─ VZLinuxBootLoader(vmlinuz, initrd.img)
       ├─ VZVirtioFileSystemDevice  tag="rootfs"       ← rootfs（只读）
       ├─ VZVirtioSocketDevice      port=2222          ← init 控制通道
       ├─ VZVirtioSocketDevice      port=4444          ← 用户态网络栈
       ├─ VZVirtioSocketDevice      port=5555          ← FUSE-over-vsock 宿主
       └─ VZNetworkDeviceConfiguration::nat()          ← 仅 AllowAll
            │
            └─ Linux 微型虚拟机（arm64）
                 tokimo-sandbox-init（PID 1）通过 virtio-vsock 通信
```

- **无服务、不需要 root。** 纯库调用；每个 `Sandbox` 启动自己的虚拟机。
- **共享文件系统：** 所有挂载使用 **FUSE-over-vsock** —— 宿主在 vsock 端口 5555 上运行进程内 `FuseHost`，每个挂载在客机中启动一个 `tokimo-sandbox-fuse` 子进程通过 vsock 连回。与 Linux 和 Windows 共同一套基础设施。
- **网络：** `AllowAll` 使用宿主侧 **smoltcp 用户态网络栈**（vsock 传输）。`Blocked` 从虚拟机配置中省略网络设备。
- **PTY：** 主 fd 留在客机中；init 通过协议 `Stdout`/`Write` 事件桥接 I/O。

### Windows — Hyper-V HCS

```
Sandbox（库） ──命名管道──▶ tokimo-sandbox-svc.exe（SYSTEM）
                                │
                                ├─ HCS 计算系统（Schema 2.5）
                                │    ├─ LinuxKernelDirect(vmlinuz, initrd)
                                │    ├─ SCSI：每会话 rootfs.vhdx
                                │    ├─ FUSE-over-vsock（用户挂载）
                                │    └─ HvSocket ServiceTable
                                │
                                ├─ AF_HYPERV 监听器（每会话 GUID）
                                │
                                └─ smoltcp 用户态网络栈
                                     │
                                     └─ NAT → 宿主网络
```

- **SYSTEM 服务**代表非管理员用户管理虚拟机。通过 `--install` 或 MSIX 一次性安装。
- **每会话隔离：** 每个会话获得独立的 VHDX 克隆和 HvSocket 服务 GUID，支持并发会话。
- **网络：** `AllowAll` 使用与 macOS 相同的 **smoltcp 用户态网络栈**。`Blocked` 在内核参数中设置 `tokimo.net=blocked`。
- **PTY：** 与 macOS 相同——主 fd 留在客机，I/O 通过协议桥接。

## 用户态网络栈

三个后端的 `AllowAll` 策略使用同一套 **smoltcp L3/L4 代理**（`src/netstack/`）。一套统一的网络栈，一个拦截点，不区分平台。

```
Linux 客机内核
  │ 以太网帧
  │   Linux：  通过 TAP tk0 → STREAM socketpair
  │   macOS：  通过 virtio-vsock
  │   Windows：通过 HvSocket
  ▼
StreamDevice（smoltcp，宿主侧）
  │
  ├─ TCP：smoltcp socket → 宿主 TcpStream::connect() → 双向代理
  ├─ UDP：smoltcp socket → 宿主 UdpSocket → 手动构造以太网回复帧
  └─ ICMP：解析 EchoRequest → 平台特定 send_echo → 构造 EchoReply
```

- **三平台统一** — Linux（TAP + socketpair）、macOS（vsock）、Windows（HvSocket）
- **双栈 IPv4/IPv6**，支持扩展头遍历（HopByHop、Route、Opts、Frag）
- **子网：** 192.168.127.0/24（v4）、fd00:7f::/64（v6），MTU 1400
- **3 线程：** RX 读取（传输层 → smoltcp）、主轮询循环、TX 写入（smoltcp → 传输层）
- **120 秒空闲超时**（每流）

## 共享 init 二进制

`tokimo-sandbox-init` 是一个 Rust 二进制，在每个沙箱中以 PID 1（或 bwrap 中的 PID 2）运行。启动时自动检测传输层：

| 传输层 | 使用者 | PTY 机制 |
|---|---|---|
| `SOCK_SEQPACKET`（继承 fd） | Linux bwrap | `SCM_RIGHTS` fd 传递 |
| `SOCK_SEQPACKET`（监听器） | Linux 独立模式 | `SCM_RIGHTS` fd 传递 |
| VSOCK 流（客机监听） | macOS VZ | 协议桥接（Stdout/Write 事件） |
| VSOCK 流（客机连接） | Windows HCS | 协议桥接（Stdout/Write 事件） |

能力：`Pipes` 和 `Pty` stdio 模式、`Resize`、`Signal`、`Killpg`、`OpenShell`、`MountFuse`/`UnmountFuse`（FUSE-over-vsock/socketpair）。

## 快速开始

```toml
[dependencies]
tokimo-package-sandbox = "0.1"
```

```rust
use tokimo_package_sandbox::{Sandbox, ConfigureParams, NetworkPolicy};

let sb = Sandbox::connect().unwrap();
sb.configure(ConfigureParams {
    user_data_name: "demo".into(),
    memory_mb: 4096,
    cpu_count: 4,
    network: NetworkPolicy::AllowAll,
    ..Default::default()
}).unwrap();

sb.create_vm().unwrap();
sb.start_vm().unwrap();

let shell = sb.shell_id().unwrap();
sb.write_stdin(&shell, b"uname -a\n").unwrap();
// ... 通过 sb.subscribe() 读取事件 ...

sb.stop_vm().unwrap();
```

## 前置条件

| 平台 | 要求 |
|---|---|
| **Linux** | `sudo apt install bubblewrap` — 运行时不需要 root。需要 `<repo>/vm/` 下的虚拟机产物（rootfs 会被绑定进 bwrap）。 |
| **macOS** | macOS 13+，Apple Silicon。需要 `<repo>/vm/` 下的虚拟机产物（见下方）。代码签名需要 `com.apple.security.virtualization` 权限。 |
| **Windows** | 启用"虚拟机平台"（Win 10 1903+）。一次性管理员权限安装服务。需要 `<repo>/vm/下的虚拟机产物。 |

### 虚拟机产物（所有平台）

三个后端共享同一套 Linux 内核 + initrd + Debian 13 rootfs。下载：

```sh
# Linux / WSL
scripts/linux/fetch-vm.sh                  # 最新发布
scripts/linux/fetch-vm.sh -t vm-v1.9.0     # 指定标签
```

```powershell
# Windows
pwsh scripts/windows/fetch-vm.ps1                 # 最新发布
pwsh scripts/windows/fetch-vm.ps1 -Tag vm-v1.9.0  # 指定标签
```

macOS 本地开发可直接符号链接预构建的 arm64 产物：

```sh
mkdir -p vm
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/vmlinuz"    vm/vmlinuz
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/initrd.img" vm/initrd.img
ln -sf "$PWD/packaging/vm-base/tokimo-os-arm64/rootfs"     vm/rootfs
```

### macOS 代码签名

在本地 `.cargo/config.toml` 中注册签名 cargo runner：

```toml
[target.aarch64-apple-darwin]
runner = "scripts/macos/codesign-and-run.sh"
```

### Windows 服务

```powershell
# 开发 — 前台运行，无 SCM
cargo run --bin tokimo-sandbox-svc -- --console

# 开发 — 持久化 SCM 服务（需要管理员）
.\target\debug\tokimo-sandbox-svc.exe --install

# 生产 — MSIX
pwsh scripts/windows/build-msix.ps1
```

## 沙箱内有什么

所有平台运行相同的 **Debian 13（Trixie）Linux rootfs**：

| 类别 | 内容 |
|---|---|
| **运行时** | Node.js 24、Python 3.13、Lua 5.4 |
| **编辑器** | vim、nano |
| **办公/文档** | pandoc、libreoffice（headless）、poppler、qpdf、tesseract-ocr |
| **Python** | pypdf、pdfplumber、reportlab、pandas、openpyxl、markitdown、ipython、requests、rich、Pillow |
| **Node.js** | pnpm、docx、pptxgenjs |
| **媒体** | ffmpeg |
| **网络** | curl、wget、dig、ping、rsync、git |
| **其他** | jq、zstd、bash-completion |

## API

### 沙箱生命周期

```rust
let sb = Sandbox::connect()?;
sb.configure(ConfigureParams { .. })?;
sb.create_vm()?;      // Windows：HCS 计算系统；Linux/macOS：无操作
sb.start_vm()?;       // Linux：启动 bwrap；macOS：启动虚拟机；Windows：启动 HCS
sb.stop_vm()?;        // 销毁
```

### Shell 控制

```rust
let shell = sb.shell_id()?;                          // 默认 shell
let job = sb.spawn_shell(ShellOpts { pty: Some((24, 80)), .. })?;  // PTY shell
sb.write_stdin(&shell, b"echo hello\n")?;
sb.resize_shell(&job, 40, 120)?;
sb.signal_shell(&job, Signal::SIGTERM)?;
sb.close_shell(&job)?;
let shells = sb.list_shells()?;
```

### 事件

```rust
let rx = sb.subscribe();
for event in rx {
    match event {
        Event::Stdout { id, data } => { /* stdout 字节 */ }
        Event::Stderr { id, data } => { /* stderr 字节 */ }
        Event::Exit { id, exit_code, signal } => { /* 进程退出 */ }
        Event::GuestConnected => { /* 客机 init 就绪 */ }
        _ => {}
    }
}
```

### 动态文件共享

```rust
sb.add_mount(Mount {
    name: "workspace".into(),
    host_path: "/tmp/my-project".into(),
    guest_path: "/workspace".into(),
    read_only: false,
})?;
// ... 客机可以访问 /workspace ...
sb.remove_mount("workspace")?;
```

## 测试

34 个集成测试，通过公共 `Sandbox` API 测试真实客机。平台无关的源码；同一套测试在三个平台上运行。

```bash
# Linux
sudo apt install bubblewrap
cargo build --bin tokimo-sandbox-init
PATH="$PWD/target/debug:$PATH" cargo test --test sandbox_integration -- --test-threads=1

# macOS
cargo test --test sandbox_integration -- --test-threads=1

# Windows（提升权限，服务运行中）
cargo test --test sandbox_integration -- --nocapture
```

Linux（bwrap 速率限制）和 macOS（VZ 调度队列串行化虚拟机启动）必须使用 `--test-threads=1`。Windows 支持并发。

覆盖范围：生命周期、Shell I/O、多 Shell 流 + 信号 + 枚举、PTY 大小/调整/ctrl-c/转义序列、FUSE 挂载添加/移除、网络 blocked/allow-all/ICMPv4/ICMPv6/IPv6 TCP、多会话并发。

单元测试：`cargo test --lib`（会话注册表、协议、服务内部）。

## 示例

```bash
# 沙箱内交互式 PTY shell
cargo run --example pty_shell

# smoltcp 网络栈独立演示（无虚拟机的 TCP + UDP 代理）
cargo run --example smoltcp_netstack
```

## 源码布局

```
src/
├── lib.rs                    公共接口，re-exports
├── api.rs                    Sandbox 句柄、ConfigureParams、Event、Mount
├── backend.rs                SandboxBackend trait（22 个方法）
├── error.rs                  Error 枚举 + Result 别名
├── platform.rs               每平台 default_backend()
├── session_registry.rs       平台无关的会话 HashMap
├── svc_protocol.rs           Windows 服务 JSON-RPC 协议
│
├── protocol/                 宿主 ↔ init 线路协议（所有后端共享）
│   ├── types.rs              Frame、Op、Reply、Event、StdioMode
│   └── wire.rs               长度前缀 JSON + SCM_RIGHTS 帧
│
├── vfs_host/                 FUSE-over-vsock/socketpair 宿主端（三平台统一）
│   ├── mod.rs                FuseHost：accept 循环、每挂载分发
│   └── id_table.rs           Nodeid + fh 分配器
│
├── vfs_protocol/             客机 ↔ 宿主 VFS 线路协议
│   ├── mod.rs                Frame、Req、Res、AttrOut、EntryOut
│   └── wire.rs               长度前缀 postcard 帧
│
├── vfs_impls.rs              LocalDirVfs：宿主目录 VfsBackend 实现
│
├── netstack/                 用户态 smoltcp L3/L4 代理（三平台统一）
│   ├── mod.rs                StreamDevice、TCP/UDP/ICMP 流代理
│   └── icmp/                 平台特定 ICMP echo 后端
│
├── linux/                    Linux 后端（bwrap，进程内）
│   ├── sandbox.rs            LinuxBackend: SandboxBackend
│   └── init_client.rs        InitClient（SOCK_SEQPACKET）
│
├── macos/                    macOS 后端（Virtualization.framework）
│   ├── sandbox.rs            MacosBackend: SandboxBackend
│   ├── vm.rs                 虚拟机引导、BOOT_LOCK
│   └── vsock_init_client.rs  VsockInitClient（VSOCK 流）
│
├── windows/                  Windows 后端（通过 SYSTEM 服务的 HCS）
│   ├── sandbox.rs            WindowsBackend: SandboxBackend
│   ├── client.rs             命名管道 JSON-RPC 客户端
│   ├── init_client.rs        WinInitClient（HvSocket）
│   ├── ov_pipe.rs            OVERLAPPED 管道封装
│   └── safe_path.rs          TOCTOU 安全路径规范化
│
└── bin/
    ├── tokimo-sandbox-init/  PID 1 客机二进制（所有平台）
    │   ├── main.rs           传输层分发、挂载设置
    │   ├── server.rs         事件循环（mio::Poll）
    │   ├── child.rs          fork/exec 辅助函数
    │   └── pty.rs            PTY 分配
    │
    ├── tokimo-sandbox-fuse/   客机侧 FUSE 桥接二进制
    │   └── main.rs           将内核 FUSE 操作翻译为 VfsProtocol 线路请求
    │
    ├── tokimo-sandbox-svc/   Windows SYSTEM 服务
    │   └── imp/
    │       ├── mod.rs        SCM 生命周期、管道服务器、会话处理
    │       ├── hcs.rs        ComputeCore.dll 加载器
    │       ├── hvsock.rs     AF_HYPERV socket 辅助函数
    │       ├── vmconfig.rs   HCS Schema 2.5 JSON 构建器
    │       └── vhdx_pool.rs  每会话 VHDX 租赁
    │
    └── tokimo-tun-pump/      客机侧 TUN pump 二进制
```

## 网络策略

| 策略 | 行为 |
|---|---|
| `AllowAll`（默认） | 通过 **smoltcp 用户态网络栈** 提供完整网络访问（所有平台）。Linux：TAP + socketpair。macOS：vsock。Windows：HvSocket。 |
| `Blocked` | 无网络。Linux：仅有 `lo` 的新网络命名空间。macOS：虚拟机配置中无网卡。Windows：内核参数 `tokimo.net=blocked`。 |

## 与 Docker 的对比

| | tokimo-package-sandbox | Docker |
|---|---|---|
| **守护进程** | 无（库调用；Windows 上为 SYSTEM 服务） | 需要 dockerd |
| **启动速度** | ~50 ms（Linux）/ ~2 s 冷启动（macOS/Windows 虚拟机） | ~1-3 s |
| **Root** | 不需要（Linux/macOS） | 通常需要 |
| **镜像** | 无（内置 Debian rootfs） | 需要 |
| **API** | Rust 原生，`Sandbox` 句柄 | CLI / REST |
| **网络** | 统一 smoltcp 用户态网络栈（所有平台） | bridge + iptables NAT |
| **用途** | "运行这条不受信任的命令" | "部署这个服务栈" |

## 许可证

MIT。见 [LICENSE](./LICENSE)。
