# Cross-platform dynamic mount → FUSE-over-vsock + VFS-shaped Driver

## Status

- [x] User approved scope (2026-05-03)
  - 三平台默认走 FUSE；Linux `--bind` / Windows Plan9 代码保留为 dead-code 仅供参考；macOS NFS 整体删除
  - Guest 端独立二进制 `tokimo-sandbox-fuse`（崩溃域与 init 隔离），用 [`fuser`](https://github.com/cberner/fuser) crate
  - Wire：独立 vsock 端口 + `u32 LE length-prefix + postcard` 二进制帧
  - Host 端 trait 形状对齐 [`tokimo-package-vfs`](https://github.com/) 的 `Driver` / `Reader` / `Mkdir` / `DeleteFile` / `DeleteDir` / `Rename` / `MoveFile` / `CopyFile` / `PutFile` / `PutStream` / `ResolveLocal`，**但定义在 sandbox crate 内部**，不引入 cargo 依赖
  - 用户在自己代码里写 ~30 行 adapter 把真正的 `tokimo-vfs::Driver` 包成 sandbox 的 `VfsBackend`
  - FUSE 默认缓存：`attr_timeout=1s` / `entry_timeout=1s` / 关 `writeback_cache`（写直通，外部修改 1 秒内可见）
- [x] Plan reviewed
- [x] Implementation (commits `a7f4a0c..86c7d5f`, macOS sandbox_integration 31/31 ✅)

---

## 1. Wire 协议

### 1.1 传输

| 平台 | 通道 | 备注 |
|---|---|---|
| macOS | `VZVirtioSocketDevice`，per-session vsock 端口（沿用 `vmconfig::alloc_session_init_port` 同款风格分配 `alloc_session_fuse_port`） | Init 控制端口与 FUSE 数据端口完全独立 |
| Windows | `AF_HYPERV` listener，per-session ServiceId（同上） | 同 init，`{port:08X}-FACB-...` 格式 |
| Linux (bwrap) | 第二条 `socketpair(AF_UNIX, SOCK_STREAM)`，CLOEXEC 在 `pre_exec` 清掉，FD 通过 `--fuse-fd=<n>` 传给 fuse 子进程 | 没有 vsock 也不用 vsock，直接 unix stream |

### 1.2 帧格式

```
+------------+---------------------+
| u32 LE len | postcard payload    |
+------------+---------------------+
```

- `len` 不含自身，单帧上限 16 MiB（READ 一次最多 1 MiB，留余量给元数据）
- payload 是一个 `enum Frame { Request(Req), Response(Res), Notify(Inval) }`，所有 op 编号显式 `#[repr(u16)]`，新加 op 必须放枚举尾部并预留 `_Reserved` 占位
- 版本协商：连接建立后第一帧 `Hello { proto_version: u16, max_inflight: u16 }`，host 回 `HelloAck`；不匹配立即关连接

### 1.3 Op 列表（与 VFS Driver 对齐 + FUSE handle 层补丁）

| FUSE op | Wire op | VfsBackend trait 调用 | 备注 |
|---|---|---|---|
| `lookup` | `Lookup { parent_nodeid, name }` | `Reader::stat` (parent_path / name) | host 分配 `nodeid: u64` 并回 `Entry { nodeid, attr, generation }` |
| `forget` | `Forget { nodeid, nlookup }` | (host 内部释放 IdTable 槽) | guest 主动清，host 不回 |
| `getattr` | `GetAttr { nodeid }` | `Reader::stat` | |
| `setattr` | `SetAttr { nodeid, attr_mask, attr }` | `Mkdir`/Truncate（无对应 trait → `EROFS`） | size/mtime/atime/uid/gid/mode；不支持的位返 `ENOSYS` |
| `readdir` / `readdirplus` | `ReadDir { nodeid, fh, offset }` | `Reader::list` | host 一次拉完目录、缓存在 `DirHandle`，按 cookie 切片返 |
| `opendir` | `OpenDir { nodeid }` | `Reader::list`（拿快照） | host 分配 `fh`，把 `Vec<FileInfo>` 缓存住 |
| `releasedir` | `ReleaseDir { fh }` | (释放 host DirHandle) | |
| `open` | `Open { nodeid, flags }` | (host 校验是否需要写) | host 分配 `fh`；写打开但 `as_put_stream() == None` → `EROFS` |
| `read` | `Read { fh, offset, size }` | `Reader::read_bytes` | size ≤ 1 MiB（kernel `max_read`） |
| `write` | `Write { fh, offset, data }` | `PutFile::put` (整文件写直通) 或 `PutStream::put_stream` | 写直通：每次 `Write` 累积到 host pending buffer，`Release/Flush` 时一次性 `put_stream`。详见 §4 |
| `flush` | `Flush { fh }` | drain pending → `PutStream::put_stream` | |
| `release` | `Release { fh }` | drain pending + 释放 fh | |
| `mkdir` | `Mkdir { parent_nodeid, name, mode }` | `Mkdir::mkdir` | |
| `rmdir` | `Rmdir { parent_nodeid, name }` | `DeleteDir::delete_dir` | |
| `unlink` | `Unlink { parent_nodeid, name }` | `DeleteFile::delete_file` | |
| `rename` | `Rename { old_parent, old_name, new_parent, new_name }` | `Rename::rename` 或 `MoveFile::move_file` | 同 parent → rename，跨 parent → move |
| `symlink` / `readlink` / `link` | (v1 不实现，返 `ENOSYS`) | — | VFS 没暴露符号链接；后续可加 |
| `statfs` | `Statfs` | (host 直接返常量：bsize=4096, 容量取自 capabilities) | |
| `fsync` | (no-op，写直通模型下 release 已落盘) | — | |
| `getxattr` / `listxattr` | (返 `ENOSYS`) | — | |

### 1.4 错误码映射

`VfsError` → `errno`（postcard 里编为 `i32`，guest fuse worker 直接 `reply_error(errno)`）：

| VfsError | errno |
|---|---|
| `NotFound` | `ENOENT` |
| `AlreadyExists` | `EEXIST` |
| `PermissionDenied` | `EACCES` |
| `NotImplemented` / `as_*() == None` | `ENOSYS` 或 `EROFS`（写类） |
| `IsDir` | `EISDIR` |
| `NotDir` | `ENOTDIR` |
| `Io(...)` | `EIO` |
| `Unauthorized` | `EACCES` |
| `Timeout` | `ETIMEDOUT` |
| 其他 | `EIO` |

### 1.5 Inval 通道（host → guest 主动失效）

```rust
enum Inval {
    Entry { parent_nodeid: u64, name: String },
    Inode { nodeid: u64, off: i64, len: i64 },
}
```

预留接口；v1 不实际驱动（VFS `file_watch` 在 `tokimo-vfs-op` 里，sandbox 不依赖它）。

---

## 2. Host 端架构

### 2.1 模块布局

```
src/
├── vfs_protocol/
│   ├── mod.rs        # Frame / Req / Res / Hello / errno 映射
│   └── wire.rs       # length-prefix codec, async read/write 帮助函数
├── vfs_backend.rs    # trait VfsBackend: VfsReader  + as_*() 可选下放
├── vfs_host/
│   ├── mod.rs        # FuseHost: 接受连接 + 路由
│   ├── id_table.rs   # IdTable: slab + (mount_id, path) ↔ nodeid，fh 同样
│   └── session.rs    # 每个 fuse 客户端连接一个 Session，跑 op loop
└── api.rs            # MountSource::Driver(Arc<dyn VfsBackend>) 变体
```

### 2.2 trait（接口形状镜像 tokimo-vfs::Driver）

```rust
// src/vfs_backend.rs —— 公开类型，零外部依赖

pub struct VfsFileInfo {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: Option<std::time::SystemTime>,
    pub mode: Option<u32>,
}

pub enum VfsError { NotFound, AlreadyExists, PermissionDenied, NotImpl,
                    IsDir, NotDir, Io(String), Unauthorized, Timeout, Other(String) }
pub type VfsResult<T> = Result<T, VfsError>;

#[async_trait::async_trait]
pub trait VfsReader: Send + Sync + 'static {
    async fn list(&self, path: &Path) -> VfsResult<Vec<VfsFileInfo>>;
    async fn stat(&self, path: &Path) -> VfsResult<VfsFileInfo>;
    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> VfsResult<Vec<u8>>;
}

pub trait VfsBackend: VfsReader {
    fn as_mkdir(&self)        -> Option<&dyn VfsMkdir>        { None }
    fn as_delete_file(&self)  -> Option<&dyn VfsDeleteFile>   { None }
    fn as_delete_dir(&self)   -> Option<&dyn VfsDeleteDir>    { None }
    fn as_rename(&self)       -> Option<&dyn VfsRename>       { None }
    fn as_move(&self)         -> Option<&dyn VfsMove>         { None }
    fn as_copy(&self)         -> Option<&dyn VfsCopy>         { None }
    fn as_put(&self)          -> Option<&dyn VfsPut>          { None }
    fn as_put_stream(&self)   -> Option<&dyn VfsPutStream>    { None }
    fn as_resolve_local(&self) -> Option<&dyn VfsResolveLocal>{ None }
}
// 各小 trait 与 tokimo-vfs::Driver 同名同签名（去掉 Driver 前缀，加 Vfs 前缀）。
```

用户 adapter（伪代码，住在他们应用 crate 里）：

```rust
struct VfsAdapter(Arc<dyn tokimo_vfs_core::Driver>);
#[async_trait] impl VfsReader for VfsAdapter { /* 直接转发 */ }
impl VfsBackend for VfsAdapter {
    fn as_put(&self) -> Option<&dyn VfsPut> { self.0.as_put().map(|p| p as &dyn VfsPut /* 透过 trait shim */) }
    // ...
}
```

### 2.3 IdTable

```rust
pub struct IdTable {
    nodes: slab::Slab<NodeEntry>,        // key = nodeid - 1
    by_path: HashMap<(MountId, PathBuf), u64>,   // 反查避免重复分配
    fhs: slab::Slab<FhEntry>,
    generation: u64,                     // 进程启动随机化，使 host 重启后旧 fh 视为 stale
}
```

- `nodeid == 1` 永远是 export root（每 mount 一个独立 root）
- `forget` 减引用计数到 0 才回收槽
- `nlookup` 计数：每次 `Lookup`/`ReadDirPlus` 返回 entry +1，guest `forget(nodeid, n)` 减 n

### 2.4 Session loop

每个 vsock/unix 连接一个 tokio task：

```text
loop {
    let req = read_frame::<Req>(&mut rx).await?;
    let id_table = self.id_table.clone();
    let backend = self.backends[req.mount_id()].clone();
    tokio::spawn(async move {
        let res = handle(req, backend, id_table).await;
        write_frame(&tx, res).await
    });
}
```

写端用 `tokio::sync::Mutex<TxHalf>` 串行化 —— FUSE 不要求按请求顺序回，
但同一帧必须原子写。

---

## 3. Guest 端 (`tokimo-sandbox-fuse` 二进制)

### 3.1 启动

```text
argv: tokimo-sandbox-fuse
        --transport=vsock --port=<N>     # macOS / Windows VM
      | --transport=unix  --fd=<N>       # Linux bwrap
        --mount=<name>:<guest_target_path>   (可重复)
```

- 由 init 在 `Configure` / `AddMount` 里 fork+exec
- 进程崩溃 → init 监听 `SIGCHLD`，向 host 上报 `MountFailed { name }`，host 决定是否拉起重启

### 3.2 fuser 配置

```rust
let opts = MountOption::FSName("tokimo-vfs".into());
let opts2 = MountOption::Subtype(name.into());
let opts3 = MountOption::AllowOther; // host 可能让 root 之外的 uid 访问
let opts4 = MountOption::DefaultPermissions;
fuser::mount2(MyFs { conn, mount_id }, &target, &[opts, opts2, opts3, opts4])?;
```

`MyFs` 实现 `fuser::Filesystem`：每个 op 翻译成 `Req` 写入 `conn`，
异步等回 `Res`，调 `reply.entry(...)` / `reply.data(...)` / `reply.error(errno)`。
TTL 字段统一填 `Duration::from_secs(1)`。

### 3.3 多 mount 的复用

一条 vsock 连接服务一个 sandbox 的所有 mount：每个 mount 在 host 侧
有独立 `mount_id: u32`，所有 wire op 第一字段就是 `mount_id`，host
路由到对应 `Arc<dyn VfsBackend>`。Guest 端则每个 mount 起一个 fuser
线程组，共享同一条 socket（`Arc<Mutex<Tx>>` + 多生产者）。

---

## 4. 写策略：写直通 + per-fh staging

由于 VFS `Driver` 没有 random-write 接口（只有 `put` 整文件 + `put_stream` 流式），
而 FUSE kernel 会发 random `write(off, len)`，必须 host 端做缓冲：

```text
open(W)   →  host 创建临时 file (memfile / tempfile)
write     →  pwrite 到临时 file
flush/release →  rewind + as_put_stream().put_stream(rx)  或 read_to_end + as_put().put
              然后 inval entry 让 stat 失效一次
```

- 缓存位置：`std::env::temp_dir()/tokimo-fuse-<session>/<fh>`
- **不设上限**：依赖定义 host tmpfs/磁盘本身的 ENOSPC 退机传递。sandbox 层再加一层是过度防御；后续如需可加 `MountOptions::write_staging_limit: Option<u64>`
- crash 路径：进程退出时 `Drop` 清空目录

> 注意：这意味着写 8 GB 文件会先在 host 临时盘缓 8 GB。对内存 VFS 这正合适；
> 对真实磁盘 driver 反而绕路。下一版可让 `VfsResolveLocal` 短路，把 FUSE
> open(W) 直接打开真实路径，跳过 staging。

---

## 5. 三平台 vsock / 端口分配

复用 `vmconfig::alloc_session_init_port` 模式，新增：

```rust
// src/bin/tokimo-sandbox-svc/imp/vmconfig.rs（Windows）
pub fn alloc_session_fuse_port() -> u32 { /* 同 init，独立计数 */ }

// macos: src/macos/vm.rs 已有 INIT_PORT 常量；新增 FUSE_PORT 计数器
```

Linux 不走 vsock，由 `LinuxBackend::start` 多创建一对 socketpair：

```rust
let (host_fuse, child_fuse) = socketpair(AF_UNIX, SOCK_STREAM)?;
// argv 加 --fuse-fd=<n>
```

---

## 6. ConfigureParams API 变化

```rust
// 旧
pub struct Mount { pub name: String, pub host_path: PathBuf, pub guest_path: PathBuf, pub read_only: bool }

// 新——只有一条路，不用枚举
pub struct Mount {
    pub name: String,
    pub guest_path: PathBuf,
    pub source: Arc<dyn VfsBackend>,
    pub read_only: bool,
}

impl Mount {
    /// 便捷构造：等价于旧 `host_path`，包 `LocalDirVfs`
    pub fn local_dir(name: impl Into<String>, guest_path: impl Into<PathBuf>, host_dir: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            guest_path: guest_path.into(),
            source: Arc::new(LocalDirVfs::new(host_dir.into())),
            read_only: false,
        }
    }
}
```

`add_mount` / `remove_mount` 同步调整参数。

**为什么不用枚举：** 用户原话是「Linux/Windows 原生方案代码保留但走不到」——这意味着 API 只暴露一条路。旧的
bwrap `--bind` / Plan9 实现仅作为源码级别的参考代码保留，加 `#[allow(dead_code)]` + 顶部注释，不从公开类型可达。

`LocalDirVfs` 是 sandbox 内自带的最小本地目录实现（`std::fs` + `tokio::fs`），让现有调用方一行迁移。

---

## 7. 删除清单（macOS NFS 移除）

- `src/macos/nfs.rs` —— 删
- `Cargo.toml`：`nfsserve` dep 删（仅 macOS target）
- `src/netstack/mod.rs`：`LocalService` 里 NFS 192.168.127.1:2049 splice 路径删
- `plan/macos-nfs-mount.md` —— 移到 `plan/done/` 或加 superseded 标注
- `docs/macos-testing.md` 里 NFS 段改写为 FUSE 段
- `tests/sandbox_integration.rs` 里 macOS-only ignore 标注（add_user_with_reverse_mount）改为正常运行

Linux/Windows 的原生 mount 实现（bwrap `--bind` / Plan9）：

- 代码加 `#[allow(dead_code)]` + 顶部注释
- `MountSource::HostPath` 仍可触达，但默认 `Mount::local_dir(...)` 走 Vfs 路径
- 不删，保留作对照实现 + 可能的 fast-path（见 §4 末尾的 ResolveLocal 短路）

---

## 8. 测试矩阵

| 用例 | Backend | 平台 |
|---|---|---|
| `MemFsVfs` (in-tree, HashMap-based) — list/stat/read/write/mkdir/unlink/rmdir/rename | 内存 | macOS / Linux / Windows |
| `LocalDirVfs` — 等价于旧 `host_path`，所有 16 个集成测试都跑 | 真实目录 | 三平台 |
| `ReadOnlyVfs` —— 验证 `as_put() == None` 时 `open(O_WRONLY)` 返 `EROFS` | 内存 | Linux |
| 大文件 read 流（1 GiB random-read） | LocalDirVfs | macOS |
| 写直通：1 GiB 顺序写 → release → 校验 host 侧落地 | LocalDirVfs | macOS |
| 多 mount 并发：8 个 mount 同时 list/read | MemFsVfs | macOS |
| Guest fuse 进程 SIGKILL → init 上报 → host 自动重新 mount | MemFsVfs | Linux |

---

## 9. 实施分阶段

1. **协议 + trait 骨架**（无平台代码）：`src/vfs_protocol/`, `src/vfs_backend.rs`, `src/vfs_host/`, in-tree `MemFsVfs` + `LocalDirVfs`
2. **Linux PoC**：`tokimo-sandbox-fuse` 二进制 + bwrap socketpair 路径，跑通 ls/cat/echo
3. **macOS 接管**：删 nfsserve，新 vsock fuse port，跑通现有 16 个集成测试
4. **Windows 接管**：service 加 fuse hvsock listener，更新 `vmconfig` 注入 `tokimo.fuse_port`
5. **写直通 + 大文件**：staging tempfile，`Release` 触发 `put_stream`
6. **清理**：plan/macos-nfs-mount.md 归档，文档与测试更新

每阶段独立 commit，每阶段集成测试全绿后再走下一步。
