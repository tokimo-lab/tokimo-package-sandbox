# Windows 沙箱初始化

本文档面向**空白 Windows 机器**，从零开始配置 `tokimo-package-sandbox` 运行环境。

## 前置条件

- Windows 10 1903+ 或 Windows 11（任意版本：Home / Pro / Enterprise）
- 硬件虚拟化已开启（Intel VT-x 或 AMD-V，BIOS 中默认开启）

## Step 1：开启虚拟机平台

打开 **Windows 功能**（Win+R → `optionalfeatures`）：

```
☑ Virtual Machine Platform
```

点击确定，**重启计算机**。

> 这是本次初始化唯一需要重启的步骤。

## Step 2：下载 TokimoOS 制品

从 [tokimo-package-rootfs Releases](https://github.com/tokimo-lab/tokimo-package-rootfs/releases) 下载最新版本，两个文件：

| 文件 | 内容 | 大小 |
|---|---|---|
| `tokimo-os-amd64.tar.zst` | Linux kernel + initrd | ~12 MB |
| `rootfs-amd64.tar.zst` | Debian rootfs | ~500 MB |

解压到你的数据目录（目录名和路径可自定义）：

```powershell
# 以 ~\.tokimo 为例，你可以改为任意路径如 D:\tokimo-os\
$TOKIMO = "$env:USERPROFILE\.tokimo"
mkdir -p $TOKIMO\kernel $TOKIMO\rootfs

# 解压 kernel + initrd
zstd -d tokimo-os-amd64.tar.zst
tar -xpf tokimo-os-amd64.tar -C $TOKIMO\

# 解压 rootfs
zstd -d rootfs-amd64.tar.zst
tar -xpf rootfs-amd64.tar -C $TOKIMO\rootfs\
```

最终目录结构：

```
$TOKIMO/
  kernel/vmlinuz      ← Linux 内核
  initrd.img          ← initramfs
  rootfs/             ← Debian 文件系统
    bin/  boot/  dev/  etc/  home/  lib/  ...
    usr/bin/node      ← Node.js 24
    usr/bin/python3   ← Python 3.13
```

## Step 3：设置环境变量（可选）

如果制品不在默认位置（`~\.tokimo/`），通过环境变量指定路径：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `TOKIMO_KERNEL` | `%USERPROFILE%\.tokimo\kernel\vmlinuz` | 内核路径 |
| `TOKIMO_INITRD` | `%USERPROFILE%\.tokimo\initrd.img` | initrd 路径 |
| `TOKIMO_ROOTFS` | `%USERPROFILE%\.tokimo\rootfs` | rootfs 目录 |
| `TOKIMO_MEMORY` | `512` | VM 内存 (MB) |
| `TOKIMO_CPUS` | `2` | vCPU 数量 |

```powershell
# 示例：制品放在 D 盘
$env:TOKIMO_KERNEL = "D:\vm\kernel\vmlinuz"
$env:TOKIMO_INITRD = "D:\vm\initrd.img"
$env:TOKIMO_ROOTFS = "D:\vm\rootfs"
```

## Step 4：代码集成

```toml
[dependencies]
tokimo-package-sandbox = "0.1"
```

```rust
use tokimo_package_sandbox::{SandboxConfig, NetworkPolicy};

let cfg = SandboxConfig::new("/tmp/work")
    .network(NetworkPolicy::Blocked);

let result = tokimo_package_sandbox::run(&["node", "-e", "console.log(1+2)"], &cfg)?;
println!("{}", result.stdout); // "3"
```

**首次调用时**库会自动通过 UAC 安装 `tokimo-sandbox-svc` 系统服务（弹窗一次，点确定）。之后所有调用完全透明，不再需要任何交互。

## 服务管理

服务二进制 `tokimo-sandbox-svc.exe` 需要与应用二进制放在同一目录：

```
your-app/
  your-app.exe
  tokimo-sandbox-svc.exe   ← 从 cargo build 输出复制
```

手动管理服务的命令（通常不需要，库自动处理）：

```powershell
# 查看状态
sc query TokimoSandboxSvc

# 手动安装/卸载
.\tokimo-sandbox-svc.exe --install
.\tokimo-sandbox-svc.exe --uninstall
```

## 工作原理

```
your-app.exe
  └─ tokimo_package_sandbox::run(["node", "-e", "1+2"])
       │
       ├─ 读取 TOKIMO_KERNEL / TOKIMO_INITRD / TOKIMO_ROOTFS
       ├─ 连接命名管道 \\.\pipe\tokimo-sandbox-svc
       │   └─ 首次：管道不存在 → UAC 安装服务 → 再连 → 成功
       └─ tokimo-sandbox-svc.exe (NT AUTHORITY\SYSTEM)
            └─ HcsCreateComputeSystem → Hyper-V 启动 Linux VM
                 ├─ mount rootfs (9p)
                 ├─ bash -c "node -e '1+2'"
                 └─ 返回 stdout/stderr/exit_code
```

## 排查

| 问题 | 解决 |
|---|---|
| `Virtual Machine Platform not enabled` | 重新执行 Step 1，确认已重启 |
| `tokimo-sandbox-svc.exe not found` | 将服务二进制复制到应用同级目录 |
| `HCS create: HRESULT 0x803701XX` | 服务未安装或未运行，执行 `--install` |
| Rootfs 文件全是 `drwxrwxrwx` | 纯 cosmetic 问题，不影响运行 |

## 相关文档

- [tokimo-package-rootfs](https://github.com/tokimo-lab/tokimo-package-rootfs) — 制品构建
- [Linux 初始化](./linux.md)
- [macOS 初始化](./macos.md)
