# tokimo-package-sandbox API 文档（中文）

跨平台 Rust 沙箱，用于在宿主机上安全运行任意命令。

- Linux：bubblewrap + seccomp BPF + POSIX rlimits
- Linux 回退：firejail + rlimits
- macOS：sandbox-exec（Seatbelt profile）+ rlimits
- Windows：在 WSL2 内再叠一层 bubblewrap

---

## 目录

1. [顶层 API](#1-顶层-api)
2. [`SandboxConfig`](#2-sandboxconfig)
3. [`NetworkPolicy`（网络开关）](#3-networkpolicy网络开关)
4. [`ResourceLimits`（资源限制）](#4-resourcelimits资源限制)
5. [`Mount`（额外挂载）](#5-mount额外挂载)
6. [`ExecutionResult`](#6-executionresult)
7. [`Session` / `JobHandle`（持久会话）](#7-session--jobhandle持久会话)
8. [`Error`](#8-error)
9. [平台实现细节](#9-平台实现细节)
10. [环境变量](#10-环境变量)
11. [调用示例速查](#11-调用示例速查)

---

## 1. 顶层 API

```rust
pub fn run<S: AsRef<str>>(cmd: &[S], cfg: &SandboxConfig) -> Result<ExecutionResult>;
```

- `cmd[0]` 是程序名，`cmd[1..]` 是参数。
- 程序在**沙箱内**的 `PATH` 里查找（默认 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`），不是宿主的 `PATH`。
- 每次 `run` 都是**一次性进程树**：namespace 在 exit 时自动销毁。跨次调用需共享状态请用 [`Session`](#7-session--jobhandle持久会话)。

源文件：`src/lib.rs:38`

---

## 2. `SandboxConfig`

```rust
pub struct SandboxConfig {
    pub name: String,
    pub work_dir: PathBuf,
    pub extra_mounts: Vec<Mount>,
    pub network: NetworkPolicy,
    pub limits: ResourceLimits,
    pub env: Vec<(OsString, OsString)>,
    pub stdin: Option<Vec<u8>>,
    pub cwd: Option<PathBuf>,
    pub stream_stderr: bool,
}
```

### 构造与 builder 方法

```rust
SandboxConfig::new(work_dir)        // 必填，必须已存在且是目录
    .name("build")                  // 仅用于日志
    .network(NetworkPolicy::Blocked)
    .limits(ResourceLimits { ... })
    .mount(Mount::ro("/opt/cache"))                 // 单个挂载
    .mounts([Mount::rw("/data")])                   // 批量
    .env("LANG", "C.UTF-8")
    .envs([("K1","V1"), ("K2","V2")])
    .stdin_str("hello\n")                           // 或 .stdin(vec![..])
    .cwd("/tmp")
    .stream_stderr(true);                           // 实时转发 stderr
```

### 字段语义

| 字段 | 语义 |
|---|---|
| `work_dir` | 沙箱内**唯一可写**的持久位置。Linux 下挂载为 `/tmp`，macOS 下等同宿主 `work_dir` 路径 |
| `extra_mounts` | 额外挂载宿主路径到沙箱（只读或读写） |
| `network` | 见 [`NetworkPolicy`](#3-networkpolicy网络开关) |
| `limits` | 见 [`ResourceLimits`](#4-resourcelimits资源限制) |
| `env` | 传给子进程的环境变量；Linux 下先 `--clearenv` 再 `--setenv`，不会泄漏宿主环境 |
| `stdin` | 可选的 stdin 字节流 |
| `cwd` | 子进程工作目录（沙箱内路径）。默认 `/tmp`（即 `work_dir` 的 guest 视图） |
| `stream_stderr` | `true` 时实时把子进程 stderr 镜像到宿主 stderr（便于调试长命令） |

默认值在 `SandboxConfig::new()` 里：`network = Blocked`，`limits = ResourceLimits::default()`。

### validate

`validate()` 是 `pub(crate)`，由 `run()` / `Session::open()` 自动调用。检查：
- `work_dir` 存在且是目录
- 每个 `Mount.host` 存在

源文件：`src/config.rs`

---

## 3. `NetworkPolicy`（网络开关）

```rust
pub enum NetworkPolicy {
    Blocked,   // 默认
    AllowAll,
}
```

> 未来规划：新增 `Observed`（eBPF cgroup/connect 可观测）与 `Gated`（slirp4netns + L7 代理，域名级 allowlist）两档。见 [`network-observability.md`](./network-observability.md)。

### Blocked（默认，完全断网）

| 平台 | 实现 |
|---|---|
| Linux / bubblewrap | `--unshare-net`：新建空的 network namespace，只有 down 的 `lo`，无网卡、无路由、DNS 解析直接失败 |
| Linux / firejail | `--net=none` |
| macOS | Seatbelt 指令 `(deny network*)`，由内核 TrustedBSD MAC 层拦截所有 socket |
| Windows | WSL 内部 bwrap 加 `--unshare-net` |

### AllowAll（完全开放）

| 平台 | 实现 |
|---|---|
| Linux / bubblewrap | `--share-net`：继承宿主 network namespace，加 `/etc/resolv.conf`、`/etc/nsswitch.conf`、`/etc/hosts`、`/etc/ssl/certs` 等 read-only 映射，DNS + HTTPS 全部可用 |
| Linux / firejail | 不加 `--net=none`，默认共享宿主网络 |
| macOS | profile 中不加 `(deny network*)`，默认放行（因为 Seatbelt 用的是 `(allow default)`） |
| Windows | WSL 内部 bwrap 加 `--share-net` |

> 注意：无论 Blocked 还是 AllowAll，Linux 下 DNS/TLS 相关的 `/etc` 文件**都**会被挂载进沙箱。差别在网络 namespace 级别——Blocked 时没有网卡可用，这些文件有也没用。

源文件：`src/config.rs:6-20`, `src/linux.rs:133-148, 201-208, 300-305`, `src/macos.rs:152-158`, `src/windows.rs:200-203`

---

## 4. `ResourceLimits`（资源限制）

```rust
pub struct ResourceLimits {
    pub max_memory_mb: u64,     // 默认 512；0 表示不设置当前内存上限
    pub timeout_secs: u64,      // 默认 30
    pub max_file_size_mb: u64,  // 默认 64
    pub max_processes: u64,     // 默认 128
}
```

### 每项限制的实现方式

| 字段 | Linux / macOS | Windows |
|---|---|---|
| `max_memory_mb` | 非 0 时设置 `RLIMIT_AS`（虚拟内存上限，`pre_exec` 设置）**加上**宿主侧轮询 `/proc/<pid>/status: VmRSS`（每 100 ms），超限则 kill 并置 `oom_killed=true`。子进程退出后也会读 `getrusage(RUSAGE_CHILDREN).ru_maxrss` 做峰值检查。`0` 表示跳过当前内存上限，用于 Go/Node/JVM 等 mmap-heavy 工具链，真实 per-sandbox 资源限制需后续 backend 实现 | 当前 WSL backend 只做 wall-clock timeout；未来 native/backend 可按平台实现 |
| `timeout_secs` | 宿主侧 wall-clock 监控线程：先 `SIGTERM`，2 秒 grace 后 `SIGKILL`。同时 `RLIMIT_CPU = timeout_secs + 5` 作为第二道保险 | 同样 wall-clock 轮询，到时 `child.kill()` |
| `max_file_size_mb` | `RLIMIT_FSIZE` | — |
| `max_processes` | **Linux 下故意不设 `RLIMIT_NPROC`**（见下） | — |

### 为什么 Linux 不用 `RLIMIT_NPROC`

`RLIMIT_NPROC` 在 Linux 是按**用户**全局计数的，不是按沙箱。如果宿主用户已经开了很多进程，`bwrap` 的 `clone()` 就会失败。所以该字段目前在 Linux 保留给未来的 cgroup per-sandbox 实现。注释见 `src/common.rs:206-212`。

### 内存限制的双重机制

```
apply_rlimits()  →  RLIMIT_AS   (max_memory_mb 非 0 时设置的 address space 硬上限)
                    RLIMIT_CPU  (CPU 秒上限)
                    RLIMIT_FSIZE
                         ↓
                    exec 子进程
                         ↓
wait_with_timeout()   max_memory_mb 非 0 时每 100 ms:
                      ├─ try_wait()                     （正常退出？）
                      ├─ elapsed > timeout?             （墙钟超时）
                      └─ VmRSS > max_memory_mb?         （RSS 超限 → kill）
                         子进程退出后还会用
                         getrusage(RUSAGE_CHILDREN).ru_maxrss 校验峰值
```

命中限制时，返回的 `ExecutionResult` 的 `timed_out` 或 `oom_killed` 会置 `true`，`exit_code = -1`。

源文件：`src/config.rs:22-52`, `src/common.rs:75-231`

---

## 5. `Mount`（额外挂载）

```rust
pub struct Mount {
    pub host: PathBuf,
    pub guest: Option<PathBuf>,  // 默认与 host 相同
    pub read_only: bool,
}
```

```rust
Mount::ro("/opt/cache")                    // 只读，host == guest
Mount::rw("/host/output").guest("/out")    // 读写，guest 改到 /out
```

Linux 上用 bwrap 的 `--ro-bind` / `--bind`；macOS 上读写 mount 会追加到 Seatbelt 的 `(allow file-write* (subpath ...))`；Windows 经 WSL 后同 Linux。

注意：macOS 的只读挂载依赖默认的 `(deny file-write*)`，本身不需要额外声明；只读文件始终可读。

源文件：`src/config.rs:54-83`

---

## 6. `ExecutionResult`

```rust
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,      // -1 表示被沙箱 kill
    pub timed_out: bool,
    pub oom_killed: bool,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out && !self.oom_killed
    }
}
```

超时或 OOM 时，`stderr` 会被追加一行说明（例如 `sandbox: killed after 30s timeout`）。

源文件：`src/result.rs`

---

## 7. `Session` / `JobHandle`（持久会话）

用于需要**跨多次调用共享状态**（env、cwd、文件、后台作业）的场景。

```rust
pub struct Session { ... }

impl Session {
    pub fn open(cfg: &SandboxConfig) -> Result<Self>;
    pub fn exec(&mut self, cmd: &str) -> Result<ExecOutput>;  // 同步执行
    pub fn spawn(&mut self, cmd: &str) -> Result<JobHandle>;  // 后台执行
    pub fn set_exec_timeout(&mut self, t: Duration);
    pub fn close(self) -> Result<()>;
}

pub struct ExecOutput { pub stdout: String, pub stderr: String, pub exit_code: i32 }

pub struct JobHandle { ... }
impl JobHandle {
    pub fn id(&self) -> u64;
    pub fn wait(self) -> Result<ExecOutput>;
    pub fn wait_with_timeout(&self, t: Duration) -> Result<ExecOutput>;
}
```

### 工作原理

`Session::open` 在沙箱内启动一个常驻的 `bash --noprofile --norc`，`stdin/stdout/stderr` 都管道化。每次 `exec(cmd)`：

1. 生成一个递增 call id + 随机 sentinel
2. 向 bash stdin 写入：`cmd`，然后紧跟一行形如 `echo __SBEND__<sid>_<id>_<rc>` 到 stdout 和 stderr
3. 两个后台 reader 线程解析各自流上的 sentinel，拆分出属于本次 exec 的 stdout/stderr/exit_code
4. 条件变量唤醒调用方

隔离等级与 `run()` 完全相同（同一个 bwrap / Seatbelt / WSL 配置），只是进程是长生命周期的。

### 使用示例

```rust
let cfg = SandboxConfig::new("/tmp/work");
let mut sess = Session::open(&cfg)?;

sess.exec("touch hello")?;
let out = sess.exec("ls")?;
assert!(out.stdout.contains("hello"));

sess.exec("export FOO=bar")?;
assert_eq!(sess.exec("echo $FOO")?.stdout.trim(), "bar");

// 后台作业
let job = sess.spawn("sleep 3 && echo done")?;
// ...做别的事...
let result = job.wait()?;

sess.close()?;
```

源文件：`src/session.rs`

---

## 8. `Error`

```rust
pub enum Error {
    Validation(String),        // 配置错误（work_dir 不存在等）
    ToolNotFound(String),      // bwrap/firejail/WSL 缺失
    Exec(String),              // spawn/wait 失败
    Io(std::io::Error),
    Other(anyhow::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
```

源文件：`src/error.rs`

---

## 9. 平台实现细节

### Linux（`src/linux.rs`）

bwrap 命令构造顺序（简化）：

```
bwrap
  --unshare-all --die-with-parent           # 除 net 外全部 unshare（net 见下）
  --ro-bind /usr /usr                       # 系统工具
  --ro-bind /lib /lib  /lib64 /bin /sbin
  --ro-bind /etc/ld.so.cache ...            # 动态链接器
  --ro-bind /etc/resolv.conf ...            # DNS + TLS
  --dir /home --dir /root                   # 空的 HOME
  --bind <work_dir> /tmp                    # 唯一可写位置
  <用户 extra_mounts>
  --tmpfs ~/.ssh, ~/.aws, ~/.gnupg, ...     # 敏感目录 tmpfs 覆盖
  --dev /dev --proc /proc                   # 在 docker 内自动降级为 --dir /proc
  --unshare-net | --share-net               # 由 NetworkPolicy 决定
  --clearenv --setenv PATH ... --setenv HOME /tmp --setenv SAFEBOX 1
  --chdir <cwd>
  --seccomp 3                               # BPF 过滤器通过 fd 3 传入
  -- <user cmd...>
```

seccomp 拦截的 syscall（`src/seccomp.rs`，x86_64 + aarch64）：
- `ptrace`、`mount`、`umount2`、`pivot_root`、`chroot`
- `keyctl`、`kexec_load`、`kexec_file_load`
- `socket(AF_UNIX)` — 阻止联系宿主 unix 套接字守护进程
- `clone(CLONE_NEWUSER)` / `unshare(CLONE_NEWUSER)` — 防止 user namespace 嵌套

其他架构仍享有 bwrap 的 namespace 隔离，但没有 syscall 过滤。

tmpfs 屏蔽的敏感 HOME 目录：`.ssh .aws .gnupg .kube .docker .config .npmrc .pypirc .netrc .bash_history .zsh_history .git-credentials`（`src/linux.rs:15-28`）。

### macOS（`src/macos.rs`）

动态生成 Seatbelt profile，写入临时文件，`/usr/bin/sandbox-exec -f <profile> <cmd...>`：

```scheme
(version 1)
(allow default)
(deny mach-register) (deny mach-priv-task-port) (deny iokit-open)
(deny process-exec (regex #"^/bin/su$"))
(deny process-exec (regex #"^/usr/bin/sudo$"))

(deny file-write*)
(allow file-write* (subpath "<work_dir>"))
(allow file-write* (subpath "/private/var/folders"))
(allow file-write* (subpath "/var/folders"))
; 用户声明的 rw mounts

(deny file-read* (subpath "/etc"))
(deny file-read* (regex #"^/Users/[^/]+/\.ssh"))
; ...其他敏感路径

; NetworkPolicy::Blocked 时追加：
(deny network*)
```

### Windows（`src/windows.rs`）

拒绝原生运行（Job Objects 的 FS 隔离不够）。必须 WSL2 + 内部安装 bubblewrap。可通过 `SAFEBOX_WSL_NO_BWRAP=1` 退化为"仅 WSL 隔离"——文件系统在 WSL 内完全暴露，只隔离 Windows 宿主。

### 回退：firejail（Linux 无 bwrap 时）

```
firejail --quiet --noprofile
  --private-dev --private-tmp --private=<work_dir>
  [--net=none]
  --blacklist=~/.ssh ...  --blacklist=/etc/shadow --blacklist=/etc/sudoers
  --whitelist=<mount.host> [--read-only=...]
  -- <cmd>
```

---

## 10. 环境变量

| 环境变量 | 作用 |
|---|---|
| `SAFEBOX_DISABLE=1` | **完全禁用沙箱**，用普通 `Command` 跑。仅用于调试/对照测试，绝不要在生产开启。Windows 原生不支持 |
| `SAFEBOX_WSL_NO_BWRAP=1` | Windows 下当 WSL 内未装 bwrap 时，允许退化为"仅 WSL 隔离" |
| `SAFEBOX=1` | 沙箱自动注入到子进程的 env，供被跑脚本检测"我在沙箱里" |

---

## 11. 调用示例速查

### 一次性命令

```rust
use tokimo_package_sandbox::{SandboxConfig, NetworkPolicy, ResourceLimits, Mount};

let work = tempfile::tempdir()?;
let cfg = SandboxConfig::new(work.path())
    .network(NetworkPolicy::AllowAll)            // 联网
    .limits(ResourceLimits {
        max_memory_mb: 1024,
        timeout_secs: 60,
        max_file_size_mb: 256,
        max_processes: 256,
    })
    .mount(Mount::ro("/opt/cache"))
    .env("LANG", "C.UTF-8")
    .cwd("/tmp");

let out = tokimo_package_sandbox::run(&["bash", "-c", "curl -sSf https://example.com"], &cfg)?;
println!("exit={} stdout={}", out.exit_code, out.stdout);
```

### 持久会话

```rust
use tokimo_package_sandbox::{SandboxConfig, Session};

let mut sess = Session::open(&SandboxConfig::new("/tmp/work"))?;
sess.exec("python3 -m venv v && . v/bin/activate && pip install requests")?;
let out = sess.exec("python -c 'import requests; print(requests.__version__)'")?;
println!("{}", out.stdout);
sess.close()?;
```

### 断网（默认）

```rust
let cfg = SandboxConfig::new(work.path());   // NetworkPolicy::Blocked 是默认
```

### 严格内存/超时

```rust
let cfg = SandboxConfig::new(work.path())
    .limits(ResourceLimits {
        max_memory_mb: 128,
        timeout_secs: 5,
        max_file_size_mb: 4,
        max_processes: 16,
    });
let out = tokimo_package_sandbox::run(&["python3","-c","x=bytearray(200*1024*1024)"], &cfg)?;
assert!(out.oom_killed);
```

---

## 附：参考文件索引

| 主题 | 文件 |
|---|---|
| 公共入口 / 导出 | `src/lib.rs` |
| 配置类型 | `src/config.rs` |
| ExecutionResult | `src/result.rs` |
| Error | `src/error.rs` |
| Session / JobHandle | `src/session.rs` |
| 宿主端监控（rlimit / 超时 / OOM 轮询） | `src/common.rs` |
| Linux 沙箱 (bwrap + firejail 回退) | `src/linux.rs` |
| seccomp BPF | `src/seccomp.rs` |
| macOS Seatbelt | `src/macos.rs` |
| Windows / WSL2 | `src/windows.rs` |
