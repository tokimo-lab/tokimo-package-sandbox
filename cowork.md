# Claude Desktop 虚拟机架构分析报告

> 日期: 2026-04-29

---

## 1. 所有文件完整路径

### 1.1 应用安装目录

```
C:\Program Files\WindowsApps\Claude_1.5354.0.0_x64__pzs8sxrjxfjjc\app\
├── claude.exe                                             223,054,672 bytes   Electron 主程序
├── resources\
│   ├── app.asar                                            27,845,891 bytes   TS/JS 代码包
│   ├── chrome-native-host.exe                               1,038,160 bytes
│   ├── cowork-svc.exe                                      12,655,440 bytes   Go 语言 VM 管理服务 ← IDA 分析目标
│   ├── cowork-plugin-shim.sh                                    7,626 bytes
│   ├── smol-bin.x64.vhdx                                   37,748,736 bytes   VHDX 模板
│   ├── app.asar.unpacked\
│   │   └── node_modules\@ant\claude-native\
│   │       └── claude-native-binding.node                   1,684,304 bytes   C++ Windows API 绑定
│   ├── index.html                                               3,776 bytes
│   ├── *.json                                               (18 个语言文件)
│   ├── *.png / *.ico / *.ttf                                (UI 资源)
│   └── drizzle\                                             (17 个 SQL migration 文件)
```

### 1.2 VM 数据目录

```
C:\Users\William\AppData\Local\Claude-3p\
├── claude-code-vm\2.1.121\
│   ├── claude                                             247,265,920 bytes   ELF64 Guest Agent ← IDA 分析目标
│   └── .verified                                                   0 bytes
│
├── vm_bundles\claudevm.bundle\
│   ├── vmlinuz                                             14,993,800 bytes   Linux 内核 (bzImage)
│   ├── vmlinuz.zst                                         14,737,657 bytes   压缩版
│   ├── initrd                                             177,303,315 bytes   initramfs (cpio newc)
│   ├── initrd.zst                                         173,703,871 bytes   压缩版
│   ├── rootfs.vhdx                                       9,453,961,216 bytes   Linux 根文件系统 (VHDX)
│   ├── rootfs.vhdx.zst                                   2,342,440,655 bytes   压缩版
│   ├── smol-bin.vhdx                                       37,748,736 bytes   辅助工具磁盘 (VHDX)
│   ├── .auto_reinstall_attempted                                    0 bytes
│   ├── .initrd.origin                                              40 bytes
│   ├── .initrd.zst.origin                                          40 bytes
│   ├── .rootfs.vhdx.origin                                         40 bytes
│   ├── .rootfs.vhdx.zst.origin                                     40 bytes
│   ├── .vmlinuz.origin                                             40 bytes
│   └── .vmlinuz.zst.origin                                         40 bytes
│
├── logs\
│   ├── cowork_vm_node.log                                      31,047 bytes   VM 启动/运行日志
│   ├── main.log                                               232,518 bytes   应用主日志
│   ├── ssh.log                                                   1,723 bytes   SSH 连接日志
│   └── custom3p-setup.log                                         660 bytes   第三方配置日志
│
├── local-agent-mode-sessions\
│   └── f34708f8-44ad-40c3-bac5-beeb51693acb\          (accountId)
│       └── 00000000-0000-4000-8000-000000000001\       (orgId)
│           ├── local_14323ae3-df14-4f0f-bd81-db8025c6b1a0\
│           ├── local_1d0077e3-7537-4c93-941d-cc25ee9fc9c1\
│           ├── local_25f83e0a-ffc7-484e-a755-6cc66131ad38\
│           ├── local_86a68b5c-f2a6-4a5c-b5f9-68371646faf4\
│           ├── local_a19a05d4-292c-4df8-9488-40e18fd136e1\
│           ├── local_e8838fc2-1dc9-4330-ba53-66c96e398765\
│           ├── local_ed7db68f-04cc-448e-bc34-ce1b89524fbc\
│           └── skills-plugin\ (空)
│
├── claude-code\2.1.121\                    (Claude Code CLI 副本)
├── configLibrary\
│   ├── _meta.json                                                165 bytes
│   └── 5c7c9ebe-4355-405f-9666-04ddd9bbf518.json                341 bytes   推理端配置
├── claude_desktop_config.json                                    194 bytes
├── config.json                                                   133 bytes
├── developer_settings.json                                        27 bytes
├── window-state.json                                             142 bytes
├── Preferences                                                   157 bytes   Chromium 偏好
├── Local State                                                   490 bytes
├── git-worktrees.json                                             41 bytes
├── cowork-enabled-cli-ops.json                                    61 bytes
├── ant-did                                                        48 bytes
├── fcache                                                        176 bytes
├── lockfile                                                        0 bytes
├── DIPS                                                       36,864 bytes
├── SharedStorage                                               4,096 bytes
├── Cache\                                  (浏览器缓存)
├── Code Cache\                             (Chromium 代码缓存)
├── IndexedDB\                              (会话/消息存储)
├── Local Storage\
├── Session Storage\
├── blob_storage\
├── Crashpad\                               (崩溃报告)
├── sentry\                                 (错误上报)
├── Partitions\
├── Network\
├── GPUCache\
├── DawnGraphiteCache\
├── DawnWebGPUCache\
├── WebStorage\
├── Shared Dictionary\
└── title-gen\
```

### 1.3 其他 Claude 相关目录

```
C:\Users\William\AppData\Local\Claude Nest-3p\       (空目录, 旧版残留)
C:\Users\William\AppData\Local\claude-cli-nodejs\    (CLI 缓存)
C:\Users\William\.claude\                            (CLI 配置和 memory)
C:\Users\William\.local\bin\claude.exe               (CLI 入口, 在 PATH 中)
```

**总计: ~11.87 GB, 184 个文件**

---

## 2. VM 文件详情

### 2.1 VHDX 虚拟磁盘

```
C:\Users\William\AppData\Local\Claude-3p\vm_bundles\claudevm.bundle\rootfs.vhdx
  大小: 9,453,961,216 bytes (8.8 GB)
  Magic: 76 68 64 78 66 69 6C 65 ("vhdxfile")
  类型: Hyper-V 动态扩展 VHDX
  用途: Linux 根文件系统

C:\Users\William\AppData\Local\Claude-3p\vm_bundles\claudevm.bundle\smol-bin.vhdx
  大小: 37,748,736 bytes (36 MB)
  Magic: 76 68 64 78 66 69 6C 65 ("vhdxfile")
  类型: Hyper-V 动态扩展 VHDX
  用途: 辅助只读工具磁盘
  来源: 启动时从 C:\Program Files\WindowsApps\Claude_1.5354.0.0_x64__pzs8sxrjxfjjc\app\resources\smol-bin.x64.vhdx 复制
```

### 2.2 Linux 内核

```
C:\Users\William\AppData\Local\Claude-3p\vm_bundles\claudevm.bundle\vmlinuz
  大小: 14,993,800 bytes
  Magic: 4D 5A (MZ header = bzImage)
  版本: Linux 6.8 HWE (Ubuntu 22.04)
  编译器: GCC (Ubuntu 12.3.0-1u1~22.04.3)
  构建路径: /build/linux-hwe-6.8-SY9cDN6.8.0/
```

### 2.3 initrd

```
C:\Users\William\AppData\Local\Claude-3p\vm_bundles\claudevm.bundle\initrd
  大小: 177,303,315 bytes
  Magic: 30 37 30 37 30 31 ("070701" = cpio newc)
  内容: 内核模块 (.ko) + GPU/网络固件 + Intel/AMD CPU 微码
```

### 2.4 Guest Agent

```
C:\Users\William\AppData\Local\Claude-3p\claude-code-vm\2.1.121\claude
  大小: 247,265,920 bytes
  Magic: 7F 45 4C 46 02 (ELF64 x86_64)
  Class: 64-bit, Little Endian
  Type: ET_EXEC (非 PIE)
  Entry: 0x2D2F400
  OS/ABI: UNIX System V
  Machine: x86_64 (0x3E)
  Program Headers: 10
  Section Headers: 42
  动态链接器: /lib64/ld-linux-x86-64.so.2

  语言组成 (从二进制字符串提取):
    Rust:   rustc c61a3a44d1a5bee35914cada6c788a05e0808f5b (nightly), 33+ std 源文件路径
    C++:    JavaScriptCore (JSC) — DFG/FTL/B3 JIT 编译器, mangled JSC:: 和 WTF:: 符号
    JS:     大量压缩的 JavaScript 代码段

  JS 引擎 (前 200MB 扫描):
    JavaScriptCore  4,881 引用  主引擎 (LLInt → Baseline → DFG → FTL JIT 管线)
    WASI              341 引用   WebAssembly 沙箱运行时
    Node.js           333 引用   N-API 绑定 (napi_get_last_error_info 等)
    Bun               291 引用   包管理 / Node.js 兼容
    V8                123 引用   API 兼容层: Local<T> v8::HandleScope::createLocal(JSC::VM &, JSC::JSValue)
    Hermes              1 引用   HERMESATOM

  安全机制:
    apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns
    apply-seccomp: execvp
    apply-seccomp: write /proc/self/uid_map
    /sys/fs/cgroup/cpu/{id}/cpu.cfs_period_us
    /sys/fs/cgroup/cpu/{id}/cpu.cfs_quota_us
    /sys/fs/cgroup/memory/memory.soft_limit_in_bytes
```

---

## 3. cowork-svc.exe (Go Windows 服务)

```
C:\Program Files\WindowsApps\Claude_1.5354.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe
  大小: 12,655,440 bytes
  语言: Go
  Go Build ID: OgRaJDQJATIo63zU9Ezo/CiW0UWf3dCW5xhfDI9jQ/...
  模块路径: github.com/anthropics/cowork-win32-service
  入口包: github.com/anthropics/cowork-win32-service/cmd/cowork-svc
```

### 3.1 IDA Pro 确认的符号地址

```
函数:
  0x87f660  BuildHCSDocument           (*VMConfig).BuildHCSDocument
  0x8846a0  CreateComputeSystem        提交 JSON 到 HCS API
  0x8874a0  ModifyComputeSystem        (*HCSSystem).ModifyComputeSystem
  0x888060  AddPlan9Share              (*HCSSystem).AddPlan9Share
  0x888240  EnumerateComputeSystems    枚举已有 VM
  0x8888a0  OpenComputeSystem          打开已有 VM
  0x891b40  StartVM                    (*WindowsVMManager).StartVM
  0x8912e0  sendPlan9Shares            (*WindowsVMManager).sendPlan9Shares
  0x890640  AddPlan9Share              (*WindowsVMManager).AddPlan9Share
  0x89cfe0  NetworkVsockServiceGUID    VSock 服务 GUID 生成

类型 (RTYPE):
  0x9c3fe0  RTYPE_vm_HCSDocument         HCS JSON 的 Go 结构体类型
  0x95ba80  RTYPE__ptr_vm_HCSDocument    指向 HCSDocument 的指针类型
  0xa52dc0  RTYPE_vm_VMConfig            VM 配置类型
  0x991a40  RTYPE__ptr_vm_VMConfig       指向 VMConfig 的指针类型
  0x9f48e0  RTYPE_vm_HCSSystem           HCS API 封装类型
  0xa19780  RTYPE__ptr_vm_HCSSystem      指向 HCSSystem 的指针类型
  0x9b7080  RTYPE_vm_Plan9SharesParams   Plan9 共享参数类型
  0x9dad80  RTYPE_vm_Plan9ShareInfo      Plan9 共享信息类型
  0xa24000  RTYPE_vm_plan9ShareSettings  Plan9 共享设置类型
  0xa35640  RTYPE_vm_Plan9Share          Plan9 共享类型
  0x973b60  RTYPE_vm_Plan9ShareFlags     Plan9 共享标志位类型
  0x9f4460  RTYPE_vm_ComputeSystemSummary VM 摘要信息类型
```

### 3.2 JSON struct tag (从二进制提取, IDA 确认)

这些是 Go 结构体字段上的 `json:"..."` tag，直接决定 JSON 序列化时的 key 名称：

```
0x93c0b9  json:"Owner"               → HCS JSON 顶层 "Owner" 字段
0x93c0cd  json:"State"               → VM 状态字段
0x93c0f5  json:"Flags"               → Plan9 共享标志位
0x937fd7  json:"Name"                → Plan9 共享名称
0x937fe9  json:"Path"                → 磁盘/共享路径
0x937ffb  json:"Port"                → Plan9 共享端口
0x93fcfd  json:"shares"              → Plan9 共享列表
0x94b1fb  json:"AccessName"          → Plan9 访问名
0x94e7f9  json:"ResourcePath"        → HCS 资源路径
0x94cf6d  json:"RequestType"         → HCS 请求类型
0x94fdb2  json:"memoryMB,omitempty"  → VM 内存配置 (MB)
0x94fdd6  json:"cpuCount,omitempty"  → VM CPU 核数
0x94fdfa  json:"memoryGB,omitempty"  → VM 内存配置 (GB)
0x94663d  json:"diskName"            → 磁盘名称
0x9438af  json:"sizeGiB"             → 磁盘大小 (GiB)
0x94fe1e  json:"hostTime,omitempty"  → 宿主机时间同步
0x952d62  json:"mac_address,omitempty" → MAC 地址
0x95325d  json:"apiProbeURL,omitempty" → API 探测地址
0x956942  json:"hostLoopbackIP,omitempty" → 宿主机回环 IP
0x94e7d7  json:"certificates"        → CA 证书
0x94b183  json:"resultJson"          → HCS 返回结果
0x948d97  json:"connected"           → 连接状态
0x943867  json:"running"             → 运行状态
0x94fd8e  json:"exitCode,omitempty"  → 退出码
0x948dae  json:"data,omitempty"      → 数据载荷
0x94b106  json:"error,omitempty"     → 错误信息
0x948deb  json:"httpProxy"           → HTTP 代理
0x94b1dd  json:"httpsProxy"          → HTTPS 代理
0x94390f  json:"noProxy"             → 代理例外
0x94b147  json:"bundlePath"          → Bundle 路径
```

### 3.3 HCS JSON 确认的独立字段名

以下字符串不作为 struct tag 出现（Go 默认使用字段名本身作为 JSON key），已确认存在于二进制中：

```
0x92a9a2  InitrdPath          ← LinuxKernelDirect.InitrdPath 字段
0x92247c  Owner               ← HCS JSON 顶层 "Owner" 字段
0x9224d0  Count               ← 资源计数 (CPU/Memory)
```

### 3.4 日志中确认的 HCS 格式字符串

```
[HCS] Calling HcsModifyComputeSystem
[HCS] Properties result: %s
[HCS] Result JSON: %s
Boot mode: LinuxKernelDirect (x64)
KernelCmdLine: %s
```

### 3.5 HCS JSON 生成流程 (IDA 确认)

```
BuildHCSDocument (0x87f660)
  │
  ├─ runtime.mapassign_faststr   → 构建 map[string]interface{}
  ├─ runtime.makemap_small       → 创建嵌套 map
  ├─ runtime.convTstring         → 类型转换 (string)
  ├─ runtime.convT64 / convT32  → 类型转换 (int64/int32)
  └─ 返回 []byte (JSON) + error

CreateComputeSystem (0x8846a0)
  │
  ├─ encoding_json_Marshal(&RTYPE_vm_HCSDocument)
  │     → 将 HCSDocument 结构体序列化为 JSON
  │
  ├─ golang_org_x_sys_windows_UTF16PtrFromString(id)
  │     → 转换 VM ID 为 UTF-16
  │
  └─ HcsCreateComputeSystem(id, json, ...)
        → 通过 vmcompute.dll 提交到 Hyper-V
```

---

## 4. HCS JSON 配置

**HCS JSON 不在磁盘上** — 由 `(*VMConfig).BuildHCSDocument` (`0x87f660`) 在内存中构建 `HCSDocument` 结构体，然后 `CreateComputeSystem` (`0x8846a0`) 调用 `encoding/json.Marshal(&RTYPE_vm_HCSDocument)` 序列化为 JSON，再通过 `HcsCreateComputeSystem()` 提交。

从 Windows 事件日志 (`Microsoft-Windows-Hyper-V-Compute-Admin`) 确认 HCS API 返回的字段路径：

```
$.RuntimeId                          ← 顶层 RuntimeId (早期尝试, 被 HCS 拒绝)
$.VirtualMachine.RuntimeId           ← VirtualMachine 下的 RuntimeId (后期尝试, 被 HCS 拒绝)
```

从 IDA 确认的 HCSDocument 结构体类型位于 `RTYPE_vm_HCSDocument` (`0x9c3fe0`)，该结构体字段名即为 JSON key。当前 Windows 版本的 HCS API 不接受 `RuntimeId` 字段，导致 VM 创建失败。

### 3.2 内嵌 gVisor 网络栈

```
gVisor 包路径 (从二进制提取):
  pkg/tcpip/stack.neighborEntryEntry
  pkg/tcpip/stack.packetEndpointList
  pkg/tcpip/stack.transportEndpoints
  pkg/tcpip/transport/tcp.cubicState
  pkg/tcpip/transport/tcp.dispatcher
  pkg/tcpip/transport/tcpconntrack

功能: TCP Cubic 拥塞控制, 连接跟踪 (conntrack), NAT (DNAT/SNAT),
      DHCP, ICMP/IGMP, DNS over HTTPS (dohpath)
```

---

## 4. HCS JSON 配置：当前状态

**HCS JSON 不在磁盘上。** 由 `VMConfig.BuildHCSDocument()` 运行时动态生成。

从 Windows 事件日志 (`Microsoft-Windows-Hyper-V-Compute-Admin`) 提取的 HCS 返回错误：

```
Event 11000: The specified compute system configuration is invalid:
  The virtual machine or container JSON document is invalid.
  (0xC037010D, 'Unknown object field '$.RuntimeId'')
  (0xC037010D, 'Unknown object field '$.VirtualMachine.RuntimeId'')
```

待 IDA Pro 逆向 `cowork-svc.exe` 中 `BuildHCSDocument` 函数获取完整 schema。

---

## 5. 连接栈全路径总结

```
Named Pipe (控制面):
  客户端 → cowork-svc.exe
  Pipe 读写日志证据: Pipe.onStreamRead → Socket.emit (来自 app.asar 堆栈跟踪)

HCS API:
  cowork-svc.exe → vmcompute.dll → HcsCreateComputeSystem(JSON)
  启动模式: LinuxKernelDirect (x64)
  内核参数: KernelCmdLine: %s

VSock (数据面):
  Guest AF_VSOCK ↔ Host HvSocket ServiceTable
  [HVSock] Creating listener
  [VNet] Listening for VM network connections on vsock port %d

Plan9 (文件共享):
  AddPlan9Share() → sendPlan9Shares() → HCS Plan9 Device
  vmCwd=/sessions/{random-name}/mnt/outputs
  mounts=outputs,uploads,.claude/skills,.claude/projects,.auto-memory

gVisor NAT (Guest 出站):
  VM → VSock → gVisor netstack (cowork-svc.exe 内) → Windows socket → WAN
  gvisor host-NAT IP

SSH (命令执行):
  确认: ClaudeSSHManager 管理 SSH 连接, 在网络接口变更时探测 SSH controllers
        golang.org/x/crypto/ssh 库编译在 cowork-svc.exe 中
  密钥交换: curve25519sha256, mlkem768WithCurve25519sha256 (后量子)
  密钥类型: ed25519, ecdsa, rsa, sk-ecdsa, sk-ed25519
  加密算法: chacha20Poly1305Cipher
  连接方式: genericTCPDialer, SSHForward, Bastion (跳板机)
  传输层: 未确认 — 日志中无 VSock 或端口号信息
```

---

## 6. VM 启动失败

```
根因: MSIX 文件系统虚拟化路径不匹配

cowork-svc.exe 期望:
  C:\Users\William\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\
    LocalCache\Roaming\Claude-3p\vm_bundles\claudevm.bundle\rootfs.vhdx

实际位置:
  C:\Users\William\AppData\Local\Claude-3p\
    vm_bundles\claudevm.bundle\rootfs.vhdx

日志:
  [MSIX] Filesystem not virtualized (likely Squirrel upgrade)
  failed to set VHDX path: VHDX file not found
  Skipping auto-reinstall (already attempted once)
```

---

## 7. IDA Pro 分析结果

### 7.1 cowork-svc.exe — 已确认

```
文件: C:\Program Files\WindowsApps\Claude_1.5354.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe
IDB:  C:\Users\William\Desktop\cowork-svc.exe.i64

已定位:
  BuildHCSDocument  0x87f660  构建 HCSDocument 结构体
  CreateComputeSystem 0x8846a0  调用 json.Marshal + HcsCreateComputeSystem
  StartVM           0x891b40  完整 VM 启动流程
  HCSDocument RTYPE 0x9c3fe0  HCS JSON 的 Go 类型定义

确认机制:
  json.Marshal(&RTYPE_vm_HCSDocument) → JSON → HcsCreateComputeSystem()
  Go struct 字段名即 JSON key, 无静态模板文件

已提取:
  - 20 个 json:"..." struct tag (字段→JSON key 映射)
  - 3 个直接字段名字符串 (InitrdPath, Owner, Count)
  - 完整函数调用链和类型依赖图

未完成: HCSDocument 的完整 Go runtime 类型结构体字段列表
        (Go 1.19+ 内部类型元数据格式需要进一步解析)
```

### 7.2 Guest Agent (ELF) — 待分析

```
文件: C:\Users\William\AppData\Local\Claude-3p\claude-code-vm\2.1.121\claude
大小: 247,265,920 bytes (ELF64 x86_64)
待分析: JS 引擎捆绑方式 / seccomp profile / SSH server 实现
```