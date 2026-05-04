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

## Step 2：准备 rootfs（必需）

> ⚠️ **从 v0.1.x 起，Linux 后端不再绑定宿主机 `/usr` `/bin` `/lib`。** bwrap 现在挂载 `vm/rootfs/` 作为打包根文件系统，与 macOS / Windows 共享同一份 artifact——这样三个平台 sandbox 内见到的工具版本完全一致（Node 24、Python 3、ffmpeg、libreoffice、tesseract、…）。

### 推荐：通过脚本下载预构建 rootfs

```bash
# 仓库 vm.yml 发布，tag 前缀 vm-v*。脚本依赖 curl/jq/tar/zstd。
scripts/linux/fetch-vm.sh
# 产出：vm/vmlinuz, vm/initrd.img, vm/rootfs/
```

`vm/` 目录的查找顺序（与 macOS 一致）：
1. `TOKIMO_VM_DIR` 环境变量
2. 从 `current_exe()` / `current_dir()` 向上找 `vm/`
3. `~/.tokimo/`

### 备选：本地构建

```bash
cd packaging/vm-base
bash build.sh amd64        # 需要 Docker
ln -sfn $PWD/tokimo-os-amd64/rootfs    ../../vm/rootfs
ln -sf  $PWD/tokimo-os-amd64/vmlinuz   ../../vm/vmlinuz
ln -sf  $PWD/tokimo-os-amd64/initrd.img ../../vm/initrd.img
```

如果 `vm/rootfs/` 缺失，`start_vm()` 会立即返回统一报错：

```
rootfs not found. Place vmlinuz + initrd.img + rootfs/ in <repo>/vm/
or set TOKIMO_VM_DIR. Run scripts/<platform>/fetch-vm.* to download.
```

## Step 3：环境变量（可选）

| 变量 | 说明 |
|---|---|
| `TOKIMO_VM_DIR` | 覆盖 `vm/` 目录查找路径（绝对路径，必须包含 `vmlinuz` / `initrd.img` / `rootfs/`）|

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
       │         --unshare-net
       │         --ro-bind <vm/rootfs>/{usr,bin,sbin,lib,lib64}
       │         --ro-bind <vm/rootfs>/etc/{passwd,group}      ← 打包用户表
       │         --ro-bind /etc/{resolv.conf,hosts,ssl,ca-certificates,...}  ← 仅宿主网络/CA
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
| rootfs 工具找不到 | 检查 `vm/rootfs/` 是否完整，运行 `scripts/linux/fetch-vm.sh` 重新拉取 |
| `rootfs not found. Place vmlinuz + initrd.img + rootfs/...` | `vm/` 目录缺失，运行 `scripts/linux/fetch-vm.sh` |

## 相关文档

- [Windows 初始化](./windows.md)
- [macOS 初始化](./macos.md)
- [`packaging/vm-base/`](../../packaging/vm-base/) — rootfs / kernel / initrd 构建管线
