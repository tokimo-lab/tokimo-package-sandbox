# 多用户 Workspace 架构方案

## 验收门槛

**每一行代码合并前，以下必须全绿：**

```bash
cargo test --lib                        # 7 个单元测试
cargo test --test spawn_capture         # 现有 15 个回归测试（不能有任何退化）
cargo test --test workspace             # 本方案新增的集成测试
make lint:rust                          # clippy + typecheck
```

违反此规则 = 不合规，不能合并。

## 目标

单 bwrap 容器内跑多个用户，共享 `nodejs` / `npm -g` 等全局工具，但 tmp、工作目录、进程生命周期互相隔离。

```
┌─────────────────────────────── Host ─────────────────────────────────────┐
│                                                                           │
│  Workspace                                                                │
│    ├─ spawn_init()  ← 一个 bwrap 容器，所有用户共享                       │
│    │                                                                      │
│    ├─ users: HashMap<UserId, UserHandle>                                  │
│    │   ├─ "alice" → UserHandle { client: InitClient, shell_id: "c1" }     │
│    │   ├─ "bob"   → UserHandle { client: InitClient, shell_id: "c2" }     │
│    │   └─ "carol" → UserHandle { client: InitClient, shell_id: "c3" }     │
│    │                                                                      │
│    └─ 每个 UserHandle 有独立的:                                            │
│         • InitClient (独立 SEQPACKET 连接)                                │
│         • bash REPL (独立 child，独立 stdin/stdout)                       │
│         • exec / spawn / kill_job 都走自己的 InitClient                   │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼───────────────────────┐
          │                         │                       │
     InitClient A             InitClient B            InitClient C
     (alice)                  (bob)                   (carol)
          │                         │                       │
          └──────────┬──────────────┼───────────────────────┘
                     │              │
              SEQPACKET × 3  (同一个 control.sock，多 accept)
                     │
                     ▼
┌─────────────────── 容器内 (一个 PID/mount/net namespace) ─────────────────┐
│                                                                            │
│   PID 1: tokimo-sandbox-init (multi-client mode)                           │
│     │                                                                      │
│     │  clients: HashMap<Fd, ClientState>                                   │
│     │    fd=5  → { owner: "alice", children: {"c1", "c4", ...} }           │
│     │    fd=6  → { owner: "bob",   children: {"c2", "c5", ...} }           │
│     │    fd=7  → { owner: "carol", children: {"c3", "c6", ...} }           │
│     │                                                                      │
│     ├─ c1: bash (alice)  TMPDIR=/tmp/alice  cwd=/work/alice               │
│     ├─ c2: bash (bob)    TMPDIR=/tmp/bob    cwd=/work/bob                 │
│     ├─ c3: bash (carol)  TMPDIR=/tmp/carol  cwd=/work/carol               │
│     ├─ c4: curl …  (alice 的 spawn，继承 alice 的 bash 环境)               │
│     ├─ c5: npm -g typescript  (bob 的 exec，写 /usr/lib/node_modules)      │
│     └─ c6: node server.js  (carol 的 spawn)                               │
│                                                                            │
│   共享: /usr, /bin, /lib, /home, node_modules, ...                        │
│   隔离: $TMPDIR, cwd, bash 生命周期, 超时控制                              │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## 核心改造点

### 第 1 步：init 支持多客户端（~80 行改动）

**文件**: `src/init/server.rs`

当前 `client: Option<OwnedFd>` → 改为 `clients: HashMap<RawFd, ClientState>`:

```rust
struct ClientState {
    fd: OwnedFd,
    /// 该客户端拥有的 child_id 集合（用于断开时批量清理）
    children: HashSet<String>,
}

struct State {
    base_env: Vec<(String, String)>,
    children: HashMap<String, ChildRecord>,
    child_slots: Vec<Option<String>>,
    clients: HashMap<RawFd, ClientState>,  // 新增
}
```

- `accept_client()`: 不再拒绝第二个连接，分配新 token（`TOK_CLIENT_BASE + index`）注册到 mio
- `handle_client_readable()`: 按 fd 区分，读到 EOF 时清理该客户端的所有 children
- `pump_child_stream()` / `emit_exit()` / 所有 `send_frame`: 事件回发到**正确的客户端 fd**。核心规则：
  - **Event::Stdout/Stderr/Exit 发给创建该 child 的客户端**
  - 需要在 `ChildRecord` 里加 `owner_fd: RawFd` 字段

**文件**: `src/init/child.rs`

`ChildRecord` 加一个字段:

```rust
pub struct ChildRecord {
    // ... 现有字段 ...
    pub owner_fd: RawFd,  // 哪个客户端创建了这个 child
}
```

**文件**: `src/init/main.rs` — 无需改动，listener fd 和 sigfd 照旧。

### 第 2 步：per-user 环境隔离（~40 行改动）

**文件**: `src/init/server.rs`

新增 `Op::AddUser`:

```jsonc
client → init  {
    "op": "AddUser",
    "user_id": "alice",
    "cwd": "/work/alice",          // 可选，默认 /tmp/<user_id>
    "env_overlay": [["NODE_ENV", "production"]],
    "mounts": [                     // 该用户专属 bind mount
        {"source": "/host/data/alice", "target": "/mnt/data", "read_only": false}
    ]
}
```

init 处理:
1. `mkdir -p /tmp/<user_id>` — tmp 隔离
2. `mkdir -p /work/<user_id>` — 工作目录隔离（如果不存在）
3. 合并 env: `TMPDIR=/tmp/<user_id>`, `HOME=/home/<user_id>`, 加上 `env_overlay`
4. 处理 `mounts`：逐个 `mount(source, target, "bind", ...)`（见第 5 步）
5. `spawn_child(bash, env, cwd, owner_fd=client_fd)` → 返回 child_id

`Op::RemoveUser`:
```jsonc
client → init  { "op": "RemoveUser", "user_id": "alice" }
```
1. 遍历该客户端的所有 children，逐个 `killpg(SIGKILL)` + `waitpid`
2. 可选清理: `rm -rf /tmp/<user_id>`

### 第 3 步：Host 侧 Workspace（~200 行新文件）

**新文件**: `src/workspace.rs`

```rust
pub struct WorkspaceConfig {
    pub work_dir: PathBuf,
    pub shared_mounts: Vec<Mount>,   // 所有用户可见的挂载
    pub network: NetworkPolicy,
    pub limits: ResourceLimits,
}

pub struct UserConfig {
    pub user_id: String,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub mounts: Vec<Mount>,          // 用户专属挂载
    pub exec_timeout: Duration,
}

pub struct Workspace {
    spawned: SpawnedInit,
    users: HashMap<String, UserHandle>,
    host_sock: PathBuf,
}

pub struct UserHandle {
    pub user_id: String,
    client: Arc<InitClient>,
    shell_id: String,
    timeout: Duration,
}
```

核心方法:

```rust
impl Workspace {
    /// 启动容器。所有用户共享这个 namespace。
    pub fn open(cfg: &WorkspaceConfig) -> Result<Self>;

    /// 动态添加用户。InitClient 连接到已有 control.sock，
    /// 发送 AddUser op，拿到 shell child_id。
    pub fn add_user(&mut self, cfg: &UserConfig) -> Result<()>;

    /// 移除用户。发送 RemoveUser op，关闭 InitClient。
    pub fn remove_user(&mut self, user_id: &str) -> Result<()>;

    /// 对指定用户执行命令（通过 sentinel 协议，和 Session::exec 一致）。
    pub fn exec(&self, user_id: &str, cmd: &str) -> Result<ExecOutput>;

    /// 后台 spawn（pipe mode，继承该用户 bash 的 cwd/env）。
    pub fn spawn(&self, user_id: &str, cmd: &str) -> Result<JobHandle>;

    /// 动态添加/移除该用户的 bind mount。
    pub fn add_mount(&self, user_id: &str, mount: &Mount) -> Result<()>;
    pub fn remove_mount(&self, user_id: &str, target: &str) -> Result<()>;

    /// 销毁整个容器和所有用户。
    pub fn close(self) -> Result<()>;
}
```

`Workspace::open()`:
1. 调用 `spawn_init(cfg)` → 起 bwrap 容器
2. 等待 `control.sock` 出现
3. **不连接** InitClient（由 `add_user` 按需连接）

`Workspace::add_user()`:
1. `InitClient::connect(&host_sock)` → 新的 SEQPACKET 连接
2. `client.hello()` → 握手（init 此时已是 multi-client 模式，不会拒绝）
3. 客户端构造 `Op::AddUser { ... }` → 发送
4. 收到 `Reply::Spawn { child_id, pid }` → 记录下来
5. 启动 bridge pipes + pump 线程 + sentinel reader 线程（和当前 `spawn_session_shell` 类似的逻辑，但只为这一个用户）

`Workspace::remove_user()`:
1. 发送 `Op::RemoveUser` → init 杀掉该用户的所有进程
2. 关掉 pump → reader 线程退出
3. 从 `users` map 中移除

### 第 4 步：per-user 超时隔离（~30 行改动）

当前 `Session::exec` 超时是 session 级别的——超时后整个 session 被 `close_inner()` 销毁。

Workspace 模式下，**每个用户的 exec 超时只影响那个用户的 bash**:

```rust
pub fn exec(&self, user_id: &str, cmd: &str) -> Result<ExecOutput> {
    let user = self.users.get(user_id)?;
    let deadline = Instant::now() + user.timeout;

    // 写 bash heredoc（和 Session::exec 一致）
    user.write_script(cmd)?;

    // 等待 sentinel，但超时后只杀该用户的 bash
    match user.wait_for_sentinels(deadline) {
        Ok(output) => Ok(output),
        Err(Timeout) => {
            // 只杀这个用户的 shell，不影响其他用户
            user.client.signal(&user.shell_id, libc::SIGKILL, true);
            // 重建该用户的 bash（保持用户存活）
            user.respawn_shell()?;
            Err(Error::exec("user exec timed out"))
        }
    }
}
```

关键差异：超时后 **重建该用户的 bash**，而不是销毁整个 session。其他用户不受影响。

### 第 5 步：动态 bind mount（~60 行）

init 需要能执行 `mount()`。当前 bwrap 用 `--seccomp` 装了 seccomp filter，会拦截 init 的 mount 调用。

**方案**: Workspace 模式下不装 seccomp，init 在 fork child 时自行安装 seccomp:

```rust
// init/server.rs: 新增 Op::BindMount
Op::BindMount { id, source, target, read_only } => {
    let flags = if read_only { MS_BIND | MS_RDONLY | MS_REMOUNT } else { MS_BIND };
    let res = unsafe { libc::mount(source, target, flags) };
    ack(bf, id, res);
}

// init/server.rs: 新增 Op::Unmount
Op::Unmount { id, target } => {
    let res = unsafe { libc::umount2(target, MNT_DETACH) };
    ack(bf, id, res);
}
```

- Source 是 bwrap 启动时预挂载的 host 路径（例如 `--bind /host/mounts /mnt/host`）
- init 收到 `BindMount` 后做二次 bind: `mount("/mnt/host/alice_data", "/mnt/data", MS_BIND)`
- 只需要在 `build_bwrap_command_inner` 里加一个大的预挂载目录

**安全性**: init 是受信任的二进制。用户进程通过 seccomp（init 在 fork 后安装到 child）仍然受限。

### 第 6 步：npm -g 全局共享

无需特殊处理。所有用户共享同一个 `/usr` 文件系统：

- bob 执行 `npm install -g typescript` → 写入 `/usr/lib/node_modules/typescript/`
- alice 执行 `which tsc` → `/usr/bin/tsc` → 能用
- `/usr` 是 bwrap `--ro-bind` 挂载的宿主 `/usr`，或者是容器内可写层

如果需要 npm -g 安装后持久化：在宿主机上创建 `/opt/npm_global`，bwrap 时 `--bind` 挂载到 `/usr/lib/node_modules`，`PATH` 加上对应 bin 目录。

---

## 实现顺序

| 顺序 | 步骤 | 工作量 | 可独立验证 |
|------|------|--------|-----------|
| 1 | init 多客户端 | ~80 行 | `cargo test` — 两个 InitClient 连接到同一个 init，各自 open_shell，exec 互不干扰 |
| 2 | Op::AddUser / RemoveUser | ~80 行 | `cargo test` — add_user 创建隔离 bash，exec 验证 TMPDIR/cwd 隔离，remove_user 杀掉该用户的进程 |
| 3 | Workspace 封装 | ~250 行 | `cargo test` — Workspace::open → add_user("alice") → exec/sapwn → add_user("bob") → bob.exec 看到 alice 的 npm 全局安装 → remove_user("alice") 不影响 bob |
| 4 | 超时隔离 | ~50 行 | `cargo test` — alice.exec("sleep 999") 超时，alice 的 bash 被重建，bob 的 exec 正常 |
| 5 | 动态 bind mount | ~80 行 | `cargo test` — add_mount + exec 验证文件可见，remove_mount 验证不可见 |
| 6 | init fork 后 seccomp | ~100 行 | `cargo test` — 子进程调用 mount 失败，init 调用 mount 成功 |
| 总计 | | ~640 行 | |

## 不改动的部分

- `InitClient` 无需改动——每个用户一个实例，独立连接
- `ChildHandle` / `run_oneshot` 无需改动
- pipe-mode spawn 继承机制无需改动（`inherit_from_child` 指向该用户自己的 shell child_id）
- Session（单用户）API 保持不变，作为 Workspace 的底层原语继续存在

## 测试策略

### 硬性要求

- **每完成一个步骤，现有 15 个 `spawn_capture` 测试 + 所有 lib 单元测试必须通过** — 不能有任何回归
- **每个步骤必须有独立的集成测试**覆盖新功能
- 测试文件: `tests/workspace.rs`

### 现有测试防线 (必须持续通过)

| 测试组 | 数量 | 命令 |
|--------|------|------|
| spawn_capture 全集 | 15 | `cargo test --test spawn_capture` |
| lib 单元测试 | 7 | `cargo test --lib` |
| Rust lint | — | `make lint:rust` |

### 各步骤新增测试

#### 第 1 步: init 多客户端

```
tests/workspace.rs:

test_two_clients_spawn_independent_shells
  两个 InitClient 连接同一个 init，各自 open_shell，
  各自 exec("echo CLIENT_A") / exec("echo CLIENT_B")，
  断言输出互相不串扰。

test_client_disconnect_cleans_its_children
  客户端 A spawn("sleep 60")，客户端 A 关闭连接，
  断言 init 清理了 A 的 child（waitpid 回收），
  客户端 B 不受影响。

test_three_clients_concurrent_exec
  三个客户端同时 exec，断言各自输出正确，无串扰。
```

#### 第 2 步: Op::AddUser / RemoveUser

```
test_add_user_creates_isolated_tmp
  add_user("alice")，exec("echo $TMPDIR")，断言输出包含 /tmp/alice。

test_add_user_creates_isolated_cwd
  add_user("bob", cwd="/work/bob")，exec("pwd")，断言输出 /work/bob。

test_remove_user_kills_all_processes
  add_user("alice")，spawn("sleep 60")，remove_user("alice")，
  断言 alice 的 bash 和 spawn 进程均被 kill（等待 3s 确认进程不存在）。

test_remove_user_does_not_affect_others
  add_user("alice")，add_user("bob")，remove_user("alice")，
  bob.exec("echo alive") 仍正常返回。

test_add_user_after_remove_reuses_user_id
  add_user("alice")，remove_user("alice")，add_user("alice")，
  断言成功，无 id 冲突。
```

#### 第 3 步: Workspace 封装

```
test_workspace_open_and_add_two_users
  Workspace::open → add_user("alice") → add_user("bob")，
  alice.exec + bob.exec 均正常。

test_workspace_npm_global_shared
  bob.exec("npm install -g typescript")，
  alice.exec("which tsc") 断言成功找到。

test_workspace_concurrent_spawn
  alice.spawn("sleep 2 && echo A")，bob.spawn("sleep 1 && echo B")，
  各自 wait，断言输出不串扰。

test_workspace_remove_user_then_spawn_another
  移除 alice 后 bob 的 spawn 仍正常工作。
```

#### 第 4 步: 超时隔离

```
test_user_timeout_only_kills_that_user
  alice.exec("sleep 999", timeout=1s)，断言超时 Err，
  bob.exec("echo alive") 断言正常，alice 后续 exec 也正常（bash 被重建）。

test_user_timeout_spawn_not_affected
  alice.spawn("sleep 30")，alice.exec("sleep 999", timeout=1s) 超时，
  alice 的 spawn 仍正常运行（spawn job 是独立 child，不受 bash 被杀影响）。

test_multiple_users_timeout_independently
  alice 和 bob 同时 exec("sleep 999", timeout=1s)，
  各自超时各自恢复，互不干扰。
```

#### 第 5 步: 动态 bind mount

```
test_add_mount_visible_inside_container
  add_mount(alice, host="/tmp/host_data", guest="/mnt/data")，
  alice.exec("ls /mnt/data/host_file") 断言文件可见。

test_remove_mount_not_visible
  remove_mount(alice, "/mnt/data")，
  alice.exec("ls /mnt/data") 断言 Err 或空。

test_mount_not_visible_to_other_user
  add_mount(alice, ...)，
  bob.exec("ls /mnt/data") 断言不可见（bob 的工作目录不同）。
```

#### 第 6 步: init fork 后 seccomp

```
test_child_cannot_mount
  add_user → exec("mount --bind /tmp /mnt")，断言失败（seccomp 拦截）。

test_init_can_mount
  init 端调用 mount 成功（由 add_mount 测试覆盖）。

test_existing_seccomp_behavior_unchanged
  单用户 Session::open 的 seccomp 行为不变 — spawn_capture 15 个测试仍全过。
```

### CI 检查清单

```
# 每一步完成后运行:
cargo test --lib                          # 单元测试
cargo test --test spawn_capture           # 现有 15 个回归测试
cargo test --test workspace               # 新 workspace 测试
make lint:rust                            # clippy + typecheck

# 全绿才算完成
```

## 向后兼容性结论

本次改造**完全不影响现有单用户模式**，改动全部是加法：

| 层面 | 单用户（现在） | 多用户（新增） | 互斥？ |
|------|-------------|-------------|------|
| init 客户端数 | 1 个（`Option<OwnedFd>`） | N 个（`HashMap<Fd, ClientState>`） | 1 个就是现在行为 |
| 事件路由 | 发给唯一客户端 | 按 `owner_fd` 发给创建者 | 兼容 |
| seccomp | bwrap `--seccomp` | init fork 后自装 | 两种路径分开 |
| Op 种类 | OpenShell / Spawn / ... | 新增 AddUser / RemoveUser / BindMount | 现有 Session 永不发新 Op |
| Session API | `Session::open/exec/spawn/close` | 不动 | Workspace 是独立新 API |
| 现有测试 | 全部通过 | 无影响 | — |

三层保障:
1. 多客户端 accept 1 个 = 和现在完全等价
2. `Session` 链路（`InitClient::connect → hello → OpenShell`）零改动
3. 新 Op 只在 `Workspace` 层使用，现有调用方不感知
