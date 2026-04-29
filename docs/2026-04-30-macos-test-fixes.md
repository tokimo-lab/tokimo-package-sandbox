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
- `src/session.rs` (Windows): stub 返回 `None`
- `src/windows/session.rs`: 补充 `shell_exit_code` 字段

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

所有 VZ 测试共用同一个 writable rootfs 目录 `~/.tokimo/rootfs/` 作为 virtiofs share（通过 `SharedDirectory::new(rootfs_path, writable=false)` 创建）。macOS 的 virtiofs / `VZSharedDirectory` 不允许第二个 VM 挂载已被其他 VM 占用的写入共享目录。

关键路径：
```
Fixture::new() / test setup
  → SandboxConfig::new(work_dir)
    → Session::open()
      → boot_session_vm()
        → find_rootfs()           → ~/.tokimo/rootfs/  (所有 VM 共用!)
        → SharedDirectory::new(rootfs, false)  → writable virtiofs share
        → vm.start()
```

### 已验证的修复方案

每个测试创建 rootfs 的 CoW clone（APFS `cp -cR`，瞬间完成，不占额外空间），让每个 VM 有独立的 writable virtiofs 源：

```rust
// tests/common/mod.rs
#[cfg(target_os = "macos")]
pub fn clone_rootfs_to(dest: &Path) -> Result<(), String> {
    static CLONE_LOCK: Mutex<()> = Mutex::new(());
    let _guard = CLONE_LOCK.lock()...;

    let src = tokimo_dir().join("rootfs");
    Command::new("cp").args(["-cR", "--"]).arg(&src).arg(dest).status()?;
    // Rename dest/rootfs/* → dest/* so find_rootfs sees dest/usr
    ...
}

// tests/session.rs Fixture::new()
common::clone_rootfs_to(work.path()).expect("clone rootfs");
```

**验证结果**：`cargo test --test session -- --test-threads=4` → 14/14 passed（session.rs 全部通过）。

### ⚠️ 待验证的依赖项

`clone_rootfs_to` 修复需要以下前置条件就绪才能完整应用：

1. **init binary rebuild 问题**（见下节）— env 继承测试（`vz_session.rs` 的 2 个 spawn env value 测试）需要 init binary 的 env dump 读取逻辑
2. **测试文件更新** — 除 `session.rs` 外，`vz_session.rs` 和 `vz_workspace.rs` 也需要加 `setup_work_dir()` → `clone_rootfs_to()` 调用
3. **验证 CoW clone 对 test 耗时的影响** — `cp -cR` 在 Mutex 下串行执行，14 个测试 × CoW 等待时间，需要基准测试

---

## Init Binary Rebuild 问题

### 现象

修改后的 init binary（`aarch64-unknown-linux-musl` target）编译通过，但 VM 启动后 VSOCK 连接超时：

```
Console: tokimo-init: mounted virtiofs
tokimo-init: session mode detected (TOKIMO_SANDBOX_VSOCK_PORT=1)
[tokimo-sandbox-init] finit_module(.../vsock.ko.xz) failed: Exec format error
[tokimo-sandbox-init] chroot to /mnt/work
(no "READY" or "connected VSOCK" message)
Host: VSOCK connect timed out after 15s
```

### 排查过程

| 测试 | 结果 |
|---|---|
| 备份 initrd (`initrd.img.bak`, 原始 binary) | ✅ 正常工作 |
| 纯 repack（无任何修改: gunzip→cpio→repack→gzip） | ✅ 工作 |
| revert server.rs 到原始版本 + rebuild → repack | ❌ VSOCK 超时 |
| revert server.rs + strip binary → repack | ❌ VSOCK 超时 |

**结论**：不是代码逻辑问题，而是 rebuild 环境（交叉编译 toolchain / Cargo.lock 依赖）产出二进制与原始备份不一致。`Cargo.lock` 在 `.gitignore` 中，依赖版本可能漂移。

### 待修复

1. 确认 `aarch64-unknown-linux-musl` toolchain 版本和依赖锁定
2. 将 `Cargo.lock` 从 `.gitignore` 移出（或至少锁定 init binary 的依赖版本）
3. 建立 initrd 的确定性构建流程（脚本化：build → strip → cpio → gzip → 验证）

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
- `tests/session.rs` 使用 `Fixture::new()` + `require_session!()` macro
- `tests/vz_session.rs` 每个测试手动创建 `TempDir` + `SandboxConfig`
- `tests/vz_workspace.rs` 同上
- 入口不统一，加一个新步骤（如 rootfs clone）需要每处重复

**建议**：
- 抽取 `VzTestFixture` 到 `tests/common/mod.rs`，封装 rootfs clone + SandboxConfig 构造
- 所有 macOS VZ 测试统一使用 fixture

### 4. `Workspace::exec` 的 env 追踪

**现状**：修改后 `Workspace::exec` 通过解析 `export KEY=VALUE` 字符串来追踪 env 修改。脆弱且无法处理复杂 env 修改（`source`、`eval`、反引号等）。

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
# macOS 当前正确运行方式：
cargo test --no-run && \
  for bin in target/debug/deps/session-* target/debug/deps/vz_session-* \
             target/debug/deps/vz_workspace-* target/debug/deps/windows_run-*; do
    codesign --force --sign - --entitlements vz.entitlements "$bin"
  done && \
  cargo test -- --test-threads=1

# 所有 VZ 测试需要：
#   - macOS Apple Silicon (Virtualization.framework)
#   - ~/.tokimo/ 下有 kernel/vmlinuz, initrd.img, rootfs/
#   - 测试二进制需签名 com.apple.security.virtualization entitlement
```
