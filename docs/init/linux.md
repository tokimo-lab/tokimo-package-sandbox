# Linux 沙箱初始化

本文档面向**空白 Linux 机器**，从零开始配置 `tokimo-package-sandbox` 运行环境。

## 前置条件

- Linux kernel 5.4+（支持 user namespaces）
- 内核已开启 `CONFIG_USER_NS=y`（主流发行版默认开启）

验证：

```bash
unshare --user --pid echo OK
# 输出 OK 即表示 user namespaces 可用
```

## Step 1：安装 bubblewrap

```bash
# Debian / Ubuntu
sudo apt install -y bubblewrap

# Fedora
sudo dnf install -y bubblewrap

# Arch
sudo pacman -S bubblewrap

# 验证
bwrap --version
```

## Step 2：准备 rootfs（可选）

Linux 上 bwrap 可以直接 mount 宿主机文件系统（`--ro-bind /usr /usr`），**不需要完整的 rootfs**。沙箱复用宿主机的 `/usr`、`/bin`、`/lib` 等系统目录。

如果你需要隔离的工具（如特定版本的 Node.js、Python 包），有以下选项：

### 选项 A：直接用宿主机系统

零配置，bwrap 自动 bind-mount 必要目录：

```bash
# 不需要额外准备，直接可用
```

### 选项 B：使用 TokimoOS rootfs

如果你想用预装了完整工具链的 Debian rootfs（含 Node.js、Python、pandoc、ffmpeg 等）：

```bash
# 下载预构建 rootfs（本仓库 vm.yml 发布，tag 前缀 vm-v*）
BASE=https://github.com/tokimo-lab/tokimo-package-sandbox/releases/latest/download
curl -LO $BASE/tokimo-linux-rootfs-x86_64.tar.zst
zstd -d tokimo-linux-rootfs-x86_64.tar.zst

# 解压到任意目录
mkdir -p /opt/tokimo/rootfs
tar -xpf tokimo-linux-rootfs-x86_64.tar -C /opt/tokimo/rootfs/
```

### 选项 C：用 Docker 构建自己的 rootfs

```bash
# 仓库内置构建脚本
cd packaging/vm-base
bash build.sh amd64
# 产出在 ./tokimo-os-amd64/rootfs/
```

## Step 3：设置环境变量（可选）

如果使用了外部 rootfs，通过环境变量或代码指定路径：

| 变量 | 说明 |
|---|---|
| `TOKIMO_SANDBOX_ROOTFS` | rootfs 路径（可选，仅当使用外部 rootfs） |

Linux 上通常不需要设置任何环境变量，bwrap 直接复用宿主机文件系统。

## Step 4：代码集成

```toml
[dependencies]
tokimo-package-sandbox = "0.1"
```

```rust
use tokimo_package_sandbox::{Sandbox, ConfigureParams, NetworkPolicy, ExecOpts};

let sb = Sandbox::connect().unwrap();
sb.configure(ConfigureParams {
    user_data_name: "demo".into(),
    memory_mb: 512,
    cpu_count: 2,
    network: NetworkPolicy::Blocked,
    ..Default::default()
}).unwrap();
sb.start_vm().unwrap();
let r = sb.exec(&["python3", "-c", "print(1+2)"], ExecOpts::default()).unwrap();
println!("stdout: {}", r.stdout_str());
println!("exit: {}", r.exit_code);
sb.stop_vm().unwrap();
```

## 工作原理

```
your-app
  └─ Sandbox::connect() → configure() → start_vm()
       │
       ├─ bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts
       │         --unshare-net --ro-bind /usr /bin /sbin /lib /lib64
       │         --cap-add CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_MKNOD
       │
       ├─ tokimo-sandbox-init (PID 2 inside bwrap)
       │    ├─ 控制通道：SOCK_SEQPACKET
       │    ├─ 网络栈：smoltcp TAP + STREAM socketpair
       │    └─ 文件共享：FUSE-over-socketpair（每个挂载一个 socketpair）
       │
       └─ Sandbox::exec(["python3", "-c", "print(1+2)"]) → 命令在隔离环境中执行
```

## 网络策略

| 策略 | 说明 |
|---|---|
| `Blocked` | `--unshare-net`，仅有 `lo`，无外部网络 |
| `AllowAll` | smoltcp 用户态网络栈，TAP + socketpair 桥接，全功能网络 |

## 持久会话

Linux 支持持久会话模式，复用同一个沙箱容器执行多个命令：

```rust
use tokimo_package_sandbox::{Sandbox, ConfigureParams, ExecOpts};

let sb = Sandbox::connect().unwrap();
sb.configure(ConfigureParams { .. }).unwrap();
sb.start_vm().unwrap();

let r1 = sb.exec(&["bash", "-c", "export FOO=bar && echo $FOO"], ExecOpts::default()).unwrap();
let r2 = sb.exec(&["touch", "/tmp/hello"], ExecOpts::default()).unwrap();

sb.stop_vm().unwrap();
```

## 排查

| 问题 | 解决 |
|---|---|
| `bwrap: No such file or directory` | `sudo apt install bubblewrap` |
| `unshare failed: Operation not permitted` | 内核未开启 user namespaces 或受 seccomp 限制 |
| `seccomp BPF failed` | 某些精简内核/容器环境不支持 seccomp，使用 `firejail` fallback |
| rootfs 工具找不到 | bwrap 模式下复用宿主机 `/usr`，确认宿主机已安装对应工具 |

## 相关文档

- [Windows 初始化](./windows.md)
- [macOS 初始化](./macos.md)
- [`packaging/vm-base/`](../../packaging/vm-base/) — rootfs / kernel / initrd 构建管线
