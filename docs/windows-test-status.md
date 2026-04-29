# Windows 沙箱测试状态

最后更新：2026-04-29

## 状态总览

`cargo test --test windows_run` — **6/6 通过** (≈ 9 秒)

```
test run_echo_hello       ... ok
test run_env_var_passed   ... ok
test run_exit_code_nonzero ... ok
test run_large_output     ... ok
test run_stderr_capture   ... ok
test run_stdin_piped      ... ok
```

`cargo test --test session` — Windows 上当前以 `SKIP` 跳过；session 后端实现进行中。

## 架构（一次性 `run()`）

```
┌─────────── host 进程（库）────────┐
│ tokimo_package_sandbox::run(...)  │
└────────────┬──────────────────────┘
             │ JSON over named pipe
             ▼
┌─── tokimo-sandbox-svc.exe (LocalSystem) ────┐
│  pipe server: \\.\pipe\tokimo-sandbox-svc   │
│       │                                     │
│       ▼  HCS Schema 2.5 JSON                │
│  ComputeCore.dll → create / start / poll    │
└─────────────────┬───────────────────────────┘
                  ▼  Hyper-V worker
┌── 微 VM ────────────────────────────────────┐
│ vmlinuz (Debian linux-image-amd64, 6.12.73) │
│ initrd (busybox + vsock9p + ko + init.sh)   │
│   PID 1 = init.sh                           │
│     • insmod hv_vmbus, vsock, hv_sock,      │
│       netfs, 9pnet, 9p                      │
│     • vsock9p /newroot 50001 rootshare      │
│     • vsock9p /newroot/mnt/work 50002 work  │
│     • chroot /newroot bash -c "$CMD"        │
│       <.vz_stdin >.vz_stdout 2>.vz_stderr   │
│   workspace (Plan9 over vsock) ← user dir   │
│   rootfs    (Plan9 over vsock) ← Debian fs  │
└─────────────────────────────────────────────┘
```

工作目录通过 Plan9-over-vsock 共享，所以 `.vz_stdout` / `.vz_stderr` /
`.vz_exit_code` / `.vz_stdin` 在 host 端就是工作目录里的普通文件。

## 关键设计点

| 项 | 选择 | 备注 |
|---|---|---|
| Schema | 2.5 | `LinuxKernelDirect` ≥ 2.2；2.5 接受最简 Plan9 share |
| Kernel | `linux-image-amd64`（generic） | Cloud kernel 没有 `CONFIG_VSOCKETS` |
| Modules | initrd 内 `/modules` 解压版 `.ko` | `xz -d` 后 busybox `insmod` 能直接加载 |
| Shares | 两个独立 Plan9 share，各占一个 vsock 端口 | rootshare → 50001, work → 50002；HCS 没有 virtio-fs |
| ComPort | COM1 → `\\.\pipe\tokimo-vm-com1-<vm_id>` | service 内的线程接受连接，把数据 tail 到 `C:\tokimo-debug\last-vm-com1.log` |
| Stdin | 写到 `<workspace>/.vz_stdin`，由 init.sh 在 chroot 之前 `<` 重定向 | 不需要 host↔guest 双向通道 |

## 部署目录约定

| 路径 | 内容 |
|---|---|
| `C:\tokimo\vmlinuz` | generic Debian kernel（约 12 MB） |
| `C:\tokimo\initrd.img` | busybox + vsock9p + 模块 + init.sh（约 2 MB） |
| `%USERPROFILE%\.tokimo\rootfs\` *or* `<exe-dir>\rootfs\` | 解压后的 Debian rootfs |
| `C:\tokimo-debug\` | 调试转储：`last-hcs-config.json`、`last-hcs-error.txt`、`last-vm-com1.log` |
| `C:\tokimo-debug\tokimo-sandbox-svc.exe` | 开发用 SYSTEM service 二进制（与 MSIX 安装的并行） |

环境变量：`TOKIMO_KERNEL`、`TOKIMO_INITRD`、`TOKIMO_ROOTFS`、`TOKIMO_MEMORY`、`TOKIMO_CPUS`。

## 已确认能工作

- MSIX 打包/签名/安装/卸载流程
- SYSTEM 服务启动 → 命名管道监听
- 客户端连接 → JSON 协议 → 服务处理 → 返回响应
- HCS Schema 2.5 + LinuxKernelDirect + Plan9 双 share + ComPort
- 微 VM 启动 → 模块加载 → 9p mount → chroot 执行 → 写回 `.vz_*` → poweroff
- stdin / stdout / stderr / exit code / large output / env var / cwd 全部正确

## 已知限制

1. **`NetworkPolicy::Observed / Gated` 在 Windows 不支持**（Linux/macOS 才有）。
   现在 `translate_network` 直接拒绝。
2. **`Session::open` 在 Windows 不支持**（实现中）。
   `tests/common::skip_unless_session_supported()` 在 Windows 返回 `true`。
3. **AMD CPU 嵌套虚拟化提示**：`Get-ComputerInfo` 可能显示
   `VMMonitorModeExtensions: False`，但 HCS 仍可工作（实测通过）。

## 复现完整流程

```powershell
# 1. 抓 generic kernel + 模块（在 WSL Ubuntu）
wsl -d Ubuntu-24.04 -- bash /mnt/f/tokimo-package-rootfs/scripts/fetch-generic-kernel.sh /tmp/tokimo-genkern

# 2. 重新打包 initrd（含模块）
wsl -d Ubuntu-24.04 -- bash /mnt/f/tokimo-package-rootfs/scripts/repack-initrd.sh

# 3. 部署到 C:\tokimo
Copy-Item -Force \\wsl$\Ubuntu-24.04\tmp\tokimo-genkern\vmlinuz C:\tokimo\vmlinuz
Copy-Item -Force \\wsl$\Ubuntu-24.04\tmp\tokimo-initrd.img      C:\tokimo\initrd.img

# 4. 管理员 shell 启动 debug 服务
sc.exe stop TokimoDebugSvc
Copy-Item -Force F:\tokimo-package-sandbox\target\debug\tokimo-sandbox-svc.exe C:\tokimo-debug\tokimo-sandbox-svc.exe
sc.exe start TokimoDebugSvc

# 5. 跑测试
$env:TOKIMO_KERNEL  = "C:\tokimo\vmlinuz"
$env:TOKIMO_INITRD  = "C:\tokimo\initrd.img"
$env:TOKIMO_ROOTFS  = "F:\tokimo-package-rootfs\tokimo-os-amd64\rootfs"
cargo test --test windows_run -- --nocapture --test-threads=1
```

## 调试命令备忘

```powershell
# 最近一次 VM 串口日志
Get-Content C:\tokimo-debug\last-vm-com1.log -Tail 50

# 最近一次 HCS 配置
Get-Content C:\tokimo-debug\last-hcs-config.json | ConvertFrom-Json | ConvertTo-Json -Depth 99

# VM 启动失败时的错误
Get-Content C:\tokimo-debug\last-hcs-error.txt

# MSIX 打包
pwsh -ExecutionPolicy Bypass -File .\scripts\build-msix.ps1
```

## 历史排错记录

按时间顺序撞过的坑：

1. HCS Schema 字段名：`LinuxKernel` → `LinuxKernelDirect`，`KernelPath` → `KernelFilePath`，`InitrdPath` → `InitRdPath`，`Arguments` → `KernelCmdLine`
2. SchemaVersion 2.0 → 2.5（`LinuxKernelDirect` 在 2.2 才引入）
3. `StopOnGuestCrash` 不在 schema 内
4. Plan9 `Flags` / `ReadOnly` 字段会让 Construct 拒绝 — 最简留 `Name + AccessName + Path + Port`
5. `\\?\` 路径前缀 HCS 不认 — `canonicalize_safe` 之后 strip 掉
6. `PIPE_TYPE_MESSAGE` 把 `send_response_raw` 的两次 WriteFile 当成两条独立消息 → 改 `PIPE_TYPE_BYTE`
7. `wait_and_close` 在成功路径上 close 了两次 → ntdll.dll 0xc0000005
8. MSIX AppxManifest 注释里有 `--`（非法 XML），`StartupArguments` 不在 schema 中
9. Cloud kernel 没有 vsock 支持 → 切到 generic kernel
10. Generic kernel 的 9p 是 module 不是 builtin，并且依赖 `netfs` → 必须先 insmod netfs
11. `init.sh` 顶部 `set -e` 让用户命令非零退出时直接 poweroff，写不到 `.vz_exit_code` — 改成 `set +e` 包围 chroot 段
12. stdin 文件路径错配：旧版本写到 `/.__tps_stdin`（chroot 后看不到），改成在 work 共享里放 `.vz_stdin`，由 init.sh 在 chroot 之前接管
