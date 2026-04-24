# 数据库作为文件系统：跨平台方案

## 背景

场景：手上是一个数据库（SQLite / KV / 云存储 / 自研），里面存的东西结构上很像文件树（`/projects/x/src/main.rs` → 字节内容）。AI / bash 操作文件系统，希望它们对这个 DB 生效。

要求：跨 Linux / macOS / Windows 三平台。

## 为什么不用 FUSE

跨平台 Rust in-process 虚拟文件系统**不存在**：

| OS | 机制 | Rust crate | 部署门槛 |
|---|---|---|---|
| Linux | FUSE（内核内置） | `fuser` | 装 `fuse3` |
| macOS | macFUSE（第三方 kext） | `fuser` | 用户授权 kext，企业部署困难 |
| Windows | WinFsp（独立驱动） | `winfsp-rs`（实验性） | 装 WinFsp，API 不同 |

要同时支持三家，得写三套代码。且 FUSE 的 syscall 粒度跟 DB 的事务粒度不对齐，容易出不一致。

## 推荐方案：物化 + 回写（Import / Export）

业界（OpenAI Code Interpreter、Anthropic Computer Use）都用这个模式。

```
┌──────────┐  导出  ┌─────────────┐ bwrap ┌────────┐
│ Database │ ─────▶ │ host tmpdir │ ────▶ │ sandbox│
│  (源)    │        │ (真文件)    │ bind  │  bash  │
│          │ ◀───── │             │       │        │
└──────────┘ diff+  └─────────────┘       └────────┘
             回写
```

### 三步

1. **进沙箱前**：从 DB 把相关路径物化为真实文件到 host 的 tempdir，顺手算入场快照
2. **沙箱内**：AI/bash 对真实 FS 任意操作（`cat` / `sed -i` / `grep -r` / `rm` 全部原生工作）
3. **沙箱退出后**：扫描 tempdir → 跟快照 diff → 计算变更集 → 作为**一个 DB 事务**提交

### 为什么这个方案好

- ✅ 跨平台：只用标准文件 API
- ✅ bash 原生工具全部工作（无 FUSE 兼容层）
- ✅ 性能：Linux `/tmp` 是 tmpfs（RAM）；macOS/Windows 小文件在 page cache，跟 FUSE 差别不大
- ✅ DB 语义清晰：写入是**显式事务**，不是 FUSE 每个 `write()` 走一趟
- ✅ 可审计：diff 就是 session 的 changelog
- ✅ 可回滚：tempdir 就是快照，不想要直接丢弃

## 回写同步：如何把沙箱修改写回 DB

### 结论先行

> **以"退出后全量 diff"为主（正确性），用 `notify` 监听为辅（实时反馈）。**

### 为什么不能只靠文件事件

跨平台事件库 `notify` 有三个固有坑，不适合当唯一事实来源：

| 坑 | 表现 |
|---|---|
| **rename dance** | `vim`/`sed -i`/多数编辑器：写临时文件 → rename 覆盖原文件。事件流中间状态不是真终态 |
| **事件合并/丢失** | macOS FSEvents ~500ms 延迟且合并；Linux inotify 队列溢出会丢事件；Windows 高负载合并 |
| **与 DB 事务不对齐** | `mv a b` 是多个事件，中间 commit 会看到不一致状态 |

所以：**事件流用于 UI 实时展示；写回 DB 用退出后快照 diff。**

### 架构

```
sandbox 运行期
   ├── notify-debouncer-full 监听 → 实时事件推 UI/日志
   └── 最终磁盘状态（ground truth）

sandbox 退出后
   └── 扫描 session_dir → 跟入场快照对比 → Δ → DB 单事务提交
```

### 入场快照

物化每个文件时记录：`path → (size, mtime, sha256)`。扫描时先比 `(size, mtime)`，一致跳过；不一致再算 hash，避免大文件重算。

### 退出 diff

```rust
enum Change {
    Added(PathBuf, Vec<u8>),
    Modified(PathBuf, Vec<u8>),
    Deleted(PathBuf),
}
```

遍历 `session_dir`：
- 不在快照 → `Added`
- 在快照且 hash 变 → `Modified`
- 在快照但磁盘没了 → `Deleted`

把 `Vec<Change>` 一次性丢给 DB 事务。

### 运行期事件流（可选 UX）

```rust
use notify_debouncer_full::new_debouncer;
use std::time::Duration;

let (tx, rx) = std::sync::mpsc::channel();
let mut deb = new_debouncer(Duration::from_millis(200), None, tx)?;
deb.watch(&session_dir, RecursiveMode::Recursive)?;

while let Ok(Ok(events)) = rx.recv() {
    for e in events {
        ui_log(format!("fs event: {:?}", e));
    }
}
// 沙箱退出后关闭 debouncer → 做最终 diff-and-commit
```

`notify-debouncer-full` 吸收 rename dance 和抖动，给出相对干净的事件。

## 实现细节

| 细节 | 处理 |
|---|---|
| 编辑器工件 | 扫描白名单过滤 `.*.swp` / `.DS_Store` / `~` 后缀 |
| 空目录 | 看 DB 是否关心目录节点，不关心就跳过 |
| 大文件 hash 开销 | 先比 `(size, mtime)`，一致跳过 |
| 权限/mtime | 一般不回写到 DB；不拿 mtime 做唯一标识（`touch` 能改） |
| 大规模删除 | 加删除数阈值/白名单做 safety net，防 AI 误 `rm -rf *` |
| 事务大小 | 一次 session 改几万文件就分批 commit |
| 并发 | safebox 保证只有沙箱进程写目录；host 端的 Rust 别往里写 |

## 数据量策略

| 规模 | 策略 |
|---|---|
| < 几百 MB | 全量物化整个 DB |
| 几 GB ~ 几十 GB | 按"工作上下文"物化子树（例：AI 工作于 `/projects/x`，只导出此子树） |
| TB 级 | **懒加载骨架**：物化 0 字节占位文件建立目录结构；AI 需要看时调 `db-get <path>` 拉真内容；写回时按时间戳或 `.dirty` 标记识别改动的文件 |

## 不适合物化的场景（保留）

- 沙箱里的程序需要透明 `open("/db/key")` on-demand 生成（例：虚拟设备文件）
- DB 本身是流式不是字节流（像 KV 订阅）
- 要求每次 `write()` 立刻原子 commit（而不是 session 结束）

这些只能上每平台各写一套 FUSE/WinFsp/macFUSE，没有 Rust 跨平台解。

## 相关 crates

- `notify` / `notify-debouncer-full` — 跨平台 FS 事件
- `walkdir` — 递归扫描 tempdir
- `sha2` — 文件 hash
- `tempfile` — session tempdir 管理

## 后续可能做进 safebox 的 API

考虑加个便捷封装（目前没做，手动调即可）：

```rust
tokimo_package_sandbox::run_with_sync(
    &["bash", "-c", cmd],
    &cfg,
    |export_dir| {
        // 用户填：把 DB 内容物化到 export_dir
        db.export_to(&export_dir)
    },
    |changes: Vec<Change>| {
        // 用户填：把变更集写回 DB
        db.commit(changes)
    },
)?;
```

但这会把 safebox 耦合到一个特定的同步范式。当前保持 safebox 只管沙箱、同步逻辑由调用方自行组织更干净。
