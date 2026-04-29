# macOS 测试修复报告

日期：2026-04-30

## 已修复的 Bug

### Fix 1: `exit N` 在 Session::exec() 中返回错误而非退出码

**影响范围**：跨平台（Linux / macOS VZ / Windows）

**问题**：用户在 `Session::exec("exit 7")` 时 bash 直接退出，sentinel 协议收不到标记 → exec 返回 "unexpected EOF" 错误，而非 exit code 7。

**修复**：
- `src/session.rs`: `ShellHandle` 新增 `shell_exit_code: Box<dyn FnMut() -> Option<i32> + Send>` 回调
- `Session::exec()` 的 `early_eof` 路径：先调用 `shell_exit_code`，若拿到退出码则返回 `Ok(ExecOutput{exit_code: N})`
- `src/macos/vz_session.rs`: VZ 的 `SessionLifecycle.exit_code` 已追踪退出码，接入 `shell_exit_code`
- `src/linux/mod.rs`: Linux 同
- `src/session.rs` (Windows): stub 返回 `None`（后续 commit `09c8a6a`）
- `src/windows/session.rs`: 补充 `shell_exit_code` 字段（后续 commit `09c8a6a`）

### Fix 2: `kill_job` 幂等性 + 双重 spawn

**影响范围**：macOS（Linux 原已正确）

**问题**：
1. VZ 的 `kill_spawn` 在第二次调用 `kill_job(jid)` 时失败 — child 已被 init 回收，signal 返回 "no such child" 错误。Linux 版早已用 `let _ = signal(...)` 处理。
2. VZ 的 `spawn_async` 闭包同时调用了 `spawn_pipes_inherit` (同步) + `spawn_pipes_inherit_async` (异步)，每次 spawn 创建了两个 child，其中一个泄漏。

**修复**：
- `src/macos/vz_session.rs`: `kill_spawn` 对齐 Linux — `let _ = kill_client.signal(...)` 忽略结果，始终返回 `Ok(())`
- `src/macos/vz_session.rs`: `spawn_async` 改为只调 `spawn_pipes_inherit_async`，从 `ChildHandle::child_id()` 取 child_id

### Fix 3: 动态 env 继承

**影响范围**：跨平台（Linux / macOS VZ）

**问题**：`/proc/<pid>/environ` 在 `execve()` 时冻结。bash 内 `export FOO=bar` 只修改内存中的 env hash table，不会更新 `/proc/self/environ`。导致 `spawn()` 通过 `inherit_from_child` 继承 env 时，拿不到 export 的动态修改。

**修复**（分三部分）：

1. **exec script 写入 env dump** — `src/session.rs`: 每次 eval 后追加 `export -p > /.tps_env_$$ 2>/dev/null || true`
2. **init binary 读取 dump** — `src/bin/tokimo-sandbox-init/server.rs`: `resolve_child_env()` 先读 `/.tps_env_<pid>`（`parse_export_p`），fallback `/proc/<pid>/environ`（`parse_proc_environ`）
3. **Workspace env tracking** — `src/workspace/mod.rs`: `UserHandle` 新增 `env: RefCell<Vec<(String, String)>>`，`exec()`/`spawn()` 传 `user.env` 作为 `env_overlay`；exec 后解析 `export KEY=VALUE` 更新追踪的 env

**⚠️ 待验证**：Fix 3 的 init binary 部分（第 2 点）编译通过但 rebuild 的二进制在 VM 里 VSOCK 连接失败，需要排查交叉编译环境（详见下文）。

---

## `--test-threads=1` 问题

### 现象

`cargo test`（默认并行）下所有 VZ 测试失败：
```
VM start: Internal error (code=-1): Start operation cancelled
```

### 根因

两个叠加问题导致并发测试失败：

**问题 A：共享 rootfs 写冲突**
所有 VZ 测试共用同一个 rootfs 目录 `~/.tokimo/rootfs/`。`SharedDirectory::new(path, false)` 中第二个参数 `false` 对应 Apple API 的 `readOnly=false`，即挂载为可读写。macOS virtiofs 不允许多个 VM 同时挂载同一可读写目录。

**问题 B：macOS 并发 VM 启动限制**
即使每个 VM 有独立的 rootfs，macOS Virtualization.framework 对同时启动的 VM 数量有隐式限制（大约 1 个）。超过限制时 `vm.start()` 返回 "Start operation cancelled"。

关键路径：
```
Fixture::new() / test setup
  → SandboxConfig::new(work_dir)
    → Session::open()
      → boot_session_vm()
        → find_rootfs()           → ~/.tokimo/rootfs/  (所有 VM 共用!)
        → SharedDirectory::new(rootfs, false)  → readOnly=false (可读写)
        → vm.start()              → 并发启动时 "Start operation cancelled"
```

### 已实现的修复方案

**问题 A 修复：每个测试 CoW clone rootfs**

每个测试创建 rootfs 的 CoW clone（APFS `cp -cR`，瞬间完成，不占额外空间），让每个 VM 有独立的 virtiofs 源：

```rust
// tests/common/mod.rs
#[cfg(target_os = "macos")]
pub fn clone_rootfs_to(dest: &Path) {
    let src = tokimo_dir().join("rootfs");
    Command::new("cp").args(["-cR", "--"]).arg(&src).arg(dest).status()?;
    // cp -cR src dest 创建 dest/rootfs/，需上移一层让 find_rootfs 的
    // cfg.work_dir.join("usr").exists() fallback 生效
    ...
}
```

已应用到所有三个测试文件：
- `tests/session.rs`：`Fixture::new()` 中调用 `common::clone_rootfs_to(work.path())`
- `tests/vz_session.rs`：`setup_work_dir()` helper，每个测试调用
- `tests/vz_workspace.rs`：同上

**问题 B 修复：`--test-threads=1`**

macOS Virtualization.framework 不支持真正的并发 VM 启动。即使用独立 rootfs，2+ 并发仍会 "Start operation cancelled"。唯一可靠方案是 `--test-threads=1`。

**验证结果**：

| 测试文件 | 结果 | 耗时 |
|---|---|---|
| `session.rs` (--test-threads=1) | 14/14 passed | ~320s |
| `vz_session.rs` (--test-threads=1) | 14/14 passed | ~322s |
| `vz_workspace.rs` (--test-threads=1) | 7/7 passed | ~166s |

---

## Init Binary VSOCK 回归问题（已修复）

### 根因

commit `094e413` ("windows: align with cowork") 将 guest 侧 VSOCK 从 `bind_vsock`（listen + accept）改为 `connect_vsock`（connect to host），为 Windows HCS 的 cowork 架构适配。但这破坏了 macOS VZ 的 VSOCK 模型：

| 平台 | Host 行为 | Guest 行为 | 正确模式 |
|---|---|---|---|
| macOS VZ | `socket_dev.connect(port)` → 连接 guest | 应 listen + accept | `bind_vsock` |
| Windows HCS | AF_HYPERV listen | connect to host | `connect_vsock` |

commit 后 guest 使用 `connect_vsock`（连接 CID_HOST），但 host 也用 `socket_dev.connect(port)` 连接 guest。双方都在连接，无人监听 → 超时。

### 修复

在 `src/bin/tokimo-sandbox-init/main.rs` 中恢复 `bind_vsock` 函数，并根据 `TOKIMO_SANDBOX_PRE_CHROOTED` 环境变量选择模式：

```rust
if pre_chrooted {
    // Windows HCS: host listens, guest connects.
    (connect_vsock(port)?, None, server::Transport::Vsock)
} else {
    // macOS VZ / Linux: guest listens, host connects.
    (bind_vsock(port)?, None, server::Transport::Vsock)
}
```

`bind_vsock` 会 listen → accept（阻塞等待 host 连接）→ 返回已连接的 fd，然后 `run_loop` 将其注册为 pre-connected client。

### 附带修复：`load_vsock_modules()` 路径

新增对 CI 风格 `/modules/*.ko` 布局的支持（除原有的 `/lib/modules/<kver>/...` 布局外）。

### CI `build.sh` 修复

arm64 构建新增 `vmw_vsock_virtio_transport` 模块（macOS VZ 需要的 virtio vsock 传输层）。

### 验证结果

| 测试文件 | 结果 | 耗时 |
|---|---|---|
| `session.rs` (--test-threads=1) | 14/14 passed | ~320s |
| `vz_session.rs` (--test-threads=1) | 14/14 passed | ~322s |
| `vz_workspace.rs` (--test-threads=1) | 7/7 passed | ~166s |

---

## 架构需要调整的地方

### 1. VirtioFS rootfs 共享策略

**现状**：所有 VM 共用全局 `~/.tokimo/rootfs/`，写冲突导致不能并发。

**建议**：
- **短期**（测试隔离）：每个测试 clone rootfs（上述 `clone_rootfs_to` 方案）
- **长期**（生产环境）：考虑以下之一：
  - rootfs 以 read-only 方式共享（`SharedDirectory::new(path, true)`），VM 内的写入走 tmpfs
  - 每次 Session::open() 自动创建 rootfs 快照
  - 使用 overlayfs 在 VM 内实现 copy-on-write（guest 侧解决，不依赖 host APFS）

### 2. `find_rootfs` 的 fallback 逻辑

**现状**：`find_rootfs()` 的优先级链是 env var → `~/.tokimo/rootfs/` → `cfg.work_dir`（要求含 `usr/`）。测试/生产共享同一路径。

**建议**：
- `SandboxConfig` 新增 `rootfs_path: Option<PathBuf>` 字段，允许显式指定 rootfs 路径
- `find_rootfs` 优先使用 `cfg.rootfs_path`，不再依赖隐式发现
- 测试可以直接注入 temp dir 路径，不再需要 work_dir 有 `usr/` 的 hack

### 3. 测试基础设施统一

**现状**：
- `tests/session.rs` 使用 `Fixture::new()` + `require_session!()` macro，内含 `clone_rootfs_to`
- `tests/vz_session.rs` 使用 `setup_work_dir()` helper + `skip_if_no_vz()`
- `tests/vz_workspace.rs` 同上
- `common/mod.rs` 提供 `clone_rootfs_to` 共享实现

**建议**：
- `vz_session.rs` 和 `vz_workspace.rs` 考虑也使用 `common::skip_unless_platform_ready()` 而非各自重复 `skip_if_no_vz()`
- 长期可抽取 `VzTestFixture` 统一封装 rootfs clone + SandboxConfig 构造

### 4. `Workspace::exec` 的 env 追踪

**现状**：修改后 `Workspace::exec` 通过解析 `export KEY=VALUE` 字符串来追踪 env 修改（`parse_export_cmd`）。仅处理 `export KEY=VALUE` 形式，无法处理 `export` + 变量引用、`export -n`、`declare -x`、`source`、`eval`、反引号等。Session 侧的 `export -p > /.tps_env_$$` dump 也有类似局限（需要 init binary 配合读取，见 init binary rebuild 问题）。

**建议**：
- 将 workspace user shell 改为 stateful（通过 stdin 发送命令，类似 Session::exec 的 sentinel 协议）
- 这样 env/cwd 修改自然持久化，无需 host 侧追踪
- 但这意味着 workspace 的 perf 模型变化：exec 不再是独立进程，而是串行化在同一个 shell 上

### 5. Windows target 编译验证

**现状**：Windows target (`x86_64-pc-windows-msvc`) 在 macOS 上交叉编译验证通过。但 macOS 上无法运行 Windows 测试（`tests/windows_run.rs` 在 macOS 上 3/6 pass，3/6 因 serial mode VZ vs HCS 行为差异失败）。

**建议**：
- `tests/windows_run.rs` 加 `#![cfg(target_os = "windows")]` gate，避免在非 Windows 平台运行
- 或改进 `try_run!` macro 的 skip 逻辑，覆盖 macOS VZ 的错误特征

---

## 测试运行命令

```bash
# macOS 正确运行方式（必须 --test-threads=1）：
cargo test --no-run && \
  for bin in target/debug/deps/session-* target/debug/deps/vz_session-* \
             target/debug/deps/vz_workspace-*; do
    codesign --force --sign - --entitlements vz.entitlements "$bin"
  done && \
  cargo test -- --test-threads=1

# 运行单个测试文件：
codesign --force --sign - --entitlements vz.entitlements target/debug/deps/session-* && \
  cargo test --test session -- --test-threads=1

# 所有 VZ 测试需要：
#   - macOS Apple Silicon (Virtualization.framework)
#   - ~/.tokimo/ 下有 kernel/vmlinuz, initrd.img, rootfs/
#   - 测试二进制需签名 com.apple.security.virtualization entitlement
#   - 必须 --test-threads=1（macOS VZ 不支持并发 VM 启动）
```
