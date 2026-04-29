# Windows 沙箱初始化

本文档描述 `tokimo-package-sandbox` 在 Windows 上的部署模型。架构对齐 Anthropic
Claude Desktop 的 `cowork-vm-service`：一个 LocalSystem 服务通过命名管道接收宿主进程
的请求，并调用 HCS API 启动 Hyper‑V 微 VM。

## 架构

```
┌─────────────────────┐  named pipe   ┌────────────────────────┐  HCS API   ┌──────────┐
│ host process        │ ────────────▶ │ tokimo-sandbox-svc.exe │ ─────────▶ │ HVSI VM  │
│ (this crate's lib)  │  \\.\pipe\    │ (LocalSystem service)  │  ComputeCore│ (Linux) │
└─────────────────────┘  tokimo-...   └────────────────────────┘            └──────────┘
```

* **服务**：`tokimo-sandbox-svc` 由 MSIX 注册为 LocalSystem 服务，通过
  `windows-service` crate 接入 SCM。命名管道 `\\.\pipe\tokimo-sandbox-svc` 的 SDDL
  为 `O:SYG:SYD:(A;;GA;;;SY)(A;;0x12019b;;;IU)` —— 仅 SYSTEM 完全控制，
  Interactive Users 仅有读写权限（修复了旧版 `BU` 暴露给所有本地账户的 LPE）。
* **宿主库**：`tokimo_package_sandbox` 在 Windows 上使用 `windows = "0.62"` crate 通过
  `WaitNamedPipeW` + `CreateFileW` 连接服务。**不再**包含 UAC 自动安装回退；服务必须
  通过 MSIX 预先安装。
* **VM**：服务调用 `ComputeCore.dll` 创建 HCS Schema 2.0 计算系统。两种引导模式：
  * **VHDX**（推荐）：`rootfs.vhdx` 以 SCSI 0:0 挂载，工作区通过 Plan9 共享，内核
    cmdline 包含 `tokimo.boot=vhdx`。要求 `tokimo-os` 内核能识别该标志。
  * **Plan9 root**（兼容）：工作区目录直接作为 rootfs 通过 Plan9 挂载。

## 前置条件

* Windows 10 21H1 / Windows 11 (10.0.19041+)
* 启用 Hyper‑V 平台（`Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`）
  及 Host Compute Service（默认随 Hyper‑V 安装）
* 一份 `tokimo-os` 构建：`vmlinuz` + `initrd` + 可选 `rootfs.vhdx`

## 安装

### 1. 构建 + 打包 MSIX

```powershell
# 仅打包（未签名，开发用）
pwsh ./scripts/build-msix.ps1

# 带签名（发行用，需 .pfx 证书）
pwsh ./scripts/build-msix.ps1 -PfxPath C:\certs\tokimo.pfx -PfxPassword $env:TOKIMO_PFX_PWD
```

产物：`target/msix/Tokimo.SandboxSvc.msix`。

### 2. 安装

```powershell
# 已签名包：双击或
Add-AppxPackage -Path target\msix\Tokimo.SandboxSvc.msix

# 未签名（仅开发，需启用开发者模式）
Add-AppxPackage -AllowUnsigned -Path target\msix\Tokimo.SandboxSvc.msix
```

MSIX 安装会自动注册并启动 `TokimoSandboxSvc` 服务。卸载使用 `Remove-AppxPackage`。

### 3. 部署 VM 资产

把 kernel/initrd/vhdx 放到下面任一位置（按优先级查找）：

1. 环境变量：`TOKIMO_KERNEL`、`TOKIMO_INITRD`、`TOKIMO_ROOTFS_VHDX`
2. `%USERPROFILE%\.tokimo\` 下的 `kernel\vmlinuz`、`initrd.img`、`rootfs.vhdx`
3. 与可执行文件同目录

若 `rootfs.vhdx` 不存在则回退到 Plan9 root 模式（需要 `rootfs/` 目录）。

## 运行时配置

| 设置 | 类型 | 含义 |
| --- | --- | --- |
| `TOKIMO_VERIFY_CALLER=1` | 环境变量 | 启用调用方 Authenticode 验签（默认仅记录路径，不验签） |
| `HKLM\SOFTWARE\Tokimo\SandboxSvc\VerifyCaller` | DWORD | 同上，注册表配置（`1` = 启用） |
| `TOKIMO_ROOTFS_VHDX` | 环境变量 | 显式指定 VHDX 路径 |

服务对每个请求都通过 `GetNamedPipeClientProcessId` → `OpenProcess(QUERY_LIMITED)`
→ `QueryFullProcessImageNameW` 记录调用方完整路径，并对所有客户端提交的路径执行
TOCTOU 安全规范化（拒绝 reparse point 与硬链接）。

## 网络策略

| `NetworkPolicy` | Windows 行为 |
| --- | --- |
| `Blocked` | VM 不附加任何 NIC（默认） |
| `AllowAll` | **当前未实现**。需要 HCN endpoint 编排，未完成前服务返回 `not_implemented` |
| `Observed` / `Gated` | Windows 后端不支持，构造请求时即拒绝 |

## 开发循环

```powershell
# 在不安装 MSIX 的情况下手动跑服务
cargo run --bin tokimo-sandbox-svc -- --service   # 走 SCM (需要 sc create)
cargo run --bin tokimo-sandbox-svc -- --console   # 前台调试，需要管理员

# 单测
cargo test --bin tokimo-sandbox-svc --lib
```

## 与 tokimo-os 协调

VHDX 模式需要 tokimo-os 内核 init 识别 `tokimo.boot=vhdx` 内核参数并把 `/dev/sda`
挂载为 `/`。在 tokimo-os 落地这一支持之前，请通过缺省 Plan9 root 模式运行。
