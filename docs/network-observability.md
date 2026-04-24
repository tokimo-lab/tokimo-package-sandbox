# 网络可观测性与策略控制（Roadmap）

本文档探讨如何让 `tokimo-package-sandbox` 超越目前的"二元开关"（`Blocked` / `AllowAll`），提供**可观测**与**可控制**的网络层，回答"沙箱里**什么时候**访问了**什么**，用了**什么协议**"。

---

## 1. 现状与局限

`NetworkPolicy` 目前只有两档：

| 档位 | 实现 | 问题 |
|---|---|---|
| `Blocked` | `bwrap --unshare-net`（新建空 netns） | 一刀切——无法测试任何联网行为 |
| `AllowAll` | `bwrap --share-net`（继承宿主 netns） | 完全无监控——不知道沙箱访问了什么 |

对 AI Agent / 自动化脚本 / 审计场景而言，真正需要的是"**窗**"——可见、可记录、可按需允许。

## 2. 观测维度（想清楚要看什么）

| 层 | 能看到的信息 | 适用技术 |
|---|---|---|
| **L3/L4** | `connect()` 时间戳、pid、comm、目标 IP:port、协议（TCP/UDP/ICMP） | eBPF、nflog、tcpdump |
| **L7 明文元数据** | 具体 URL、HTTP `Host`、TLS `SNI` 域名、HTTP method | 透明代理、SNI 嗅探 |
| **L7 HTTPS 内容** | 解密后的 body | MITM（需要让沙箱信任自签 CA） |
| **DNS** | 查询的域名、解析结果 | DNS 拦截/日志 |

大部分场景 L3/L4 + SNI/Host + DNS 就够了——够回答"沙箱在什么时候连了谁"，不需要解密内容。

---

## 3. 方案阶梯

### 🪶 方案 1：eBPF cgroup/connect（最轻量、最推荐起步）

给每个沙箱分配一个独立 cgroup v2，在以下 hook 上挂 eBPF 程序：

- `BPF_CGROUP_INET4_CONNECT` / `BPF_CGROUP_INET6_CONNECT` — 拦截 `connect()`
- `BPF_CGROUP_UDP4_SENDMSG` / `BPF_CGROUP_UDP6_SENDMSG` — 拦截 UDP（UDP 没有 connect）
- `BPF_CGROUP_INET_SOCK_CREATE`（可选）— 拦截 `socket()` 创建

程序能拿到的结构：

```c
struct bpf_sock_addr {
    __u32 user_family;      // AF_INET / AF_INET6
    __u32 user_ip4;         // 目标 IPv4（网络字节序）
    __u32 user_ip6[4];      // 目标 IPv6
    __u32 user_port;        // 目标端口
    __u32 family, type, protocol;  // IPPROTO_TCP / UDP / ICMP
};
// 配合 bpf_get_current_pid_tgid() 拿 pid
// 配合 bpf_get_current_comm() 拿进程名
```

**决策 & 事件上报**：
- `return 1` → 允许
- `return 0` → `EPERM`，应用层 `connect() failed`
- 通过 `BPF_MAP_TYPE_RINGBUF` 把事件结构推给 host 用户态程序做日志/审计

**优点**
- 零网络开销（kernel 快速路径）
- 按 pid / comm / 目标地址可编程决策
- 原生支持拒绝；rootless（现代内核只要 `CAP_BPF`）

**代价**
- 协议粒度到 L4，**看不到 SNI/域名**
- 需要 eBPF 工具链；本项目可用 [**Aya**](https://aya-rs.dev/)（纯 Rust eBPF，无 libbpf 依赖）

**Rust 实现栈**
- `aya` — 用户态加载器、Map 读写、ring buffer 读取
- `aya-ebpf` — `#[cgroup_sockaddr(connect4)]` 等宏
- `aya-log` — eBPF 程序里 `info!()` 回传到用户态

### 🌐 方案 2：slirp4netns + 用户态代理（L7 可见，最完整）

这是**最推荐的生产方案**——能完整回答"什么时候访问了什么，用了什么协议"，包含域名/URL 信息。

```
沙箱内进程
   │ 任意网络流量
   ▼
沙箱 netns 的 TAP 网卡  ←  slirp4netns 把 TAP 桥到用户态 TCP/IP stack
                        │
                        ▼
               你写的 Rust proxy（tokio）
               ├─ 拦截 DNS（UDP :53）→ 记录查询、代解析
               ├─ 读 TLS ClientHello 首包 → 抽取 SNI（明文）
               ├─ 读 HTTP/1.x 首行 + Host header → 抽取 URL
               ├─ 按 allowlist 决定 forward / drop
               └─ NetEvent 推给 sink
```

**能记录出的事件样例**：

```
[21:30:15.234] pid=12345 python3  DNS     UDP :53   → pypi.org? A?
[21:30:15.260] pid=12345 python3  DNS     UDP :53   ← pypi.org: 151.101.1.223
[21:30:15.511] pid=12345 python3  TCP     151.101.1.223:443  CONNECT
[21:30:15.530] pid=12345 python3  TLS/SNI TCP 151.101.1.223:443  SNI=pypi.org
[21:30:15.830] pid=12345 python3  HTTP    GET pypi.org/simple/requests
[21:30:15.830]                    ├─ verdict: ALLOW (matches "pypi.org")
```

**优点**
- Rootless（slirp4netns 就是 Podman 无 root 模式用的那个）
- 粒度从 L3 到 L7，SNI/Host 域名完整
- 天然支持 allowlist（"只准访问 pypi 和 GitHub"之类）
- 加密内容看不到，但**元数据完全透明**

**代价**
- 吞吐约 1 Gbps 上限（纯用户态 TCP stack）——对 AI tool / 包管理器场景绰绰有余
- 要写代理逻辑。SNI 解析 ~50 行 Rust；DNS 解析 ~100 行；HTTP 首行 ~30 行

### 🔍 方案 3：veth + tcpdump / nflog（纯旁路观察）

不拦截，只记录：

```
宿主 ── veth_host ── veth_sbx ── 沙箱 netns
          │
          └─ tcpdump -i veth_host -w live.pcap
             或 iptables -A FORWARD -i veth_host -j NFLOG --nflog-group 5
                NFLOG → netlink → 你的 Rust 进程
```

**优点**
- 真实 packet trace，事后可 Wireshark 分析
- 最透明，应用层完全无感

**代价**
- 需要 `CAP_NET_ADMIN`（建 veth + 改 netns）
- L3/L4 可见，L7 仅 SNI（除非 MITM）
- 仅观察，无法阻断特定目标

### 🔐 方案 4：Full MITM（看 HTTPS body 明文）

方案 2 的增强：proxy 终止 TLS，生成 per-domain 证书，沙箱 `/etc/ssl/certs` 注入你的自签 CA。

**优点**：HTTPS body 解密可见。
**代价**
- 对 CA-pinning 的客户端会失败（pip --cert 指定 / Go net/http 的 strict mode）
- 隐私/合规风险更高
- **不建议作为默认档位**，作为 debug/insp-class 才开启

---

## 4. 建议的 API 扩展

```rust
pub enum NetworkPolicy {
    Blocked,                                // 现有，netns 隔离
    AllowAll,                               // 现有，继承宿主 netns

    /// L3/L4 可观测 — 通过 eBPF cgroup/connect 报告所有网络尝试。
    /// 默认放行，sink 收到事件后可以异步处理（记录、推 Kafka 等）。
    /// 若 sink 返回 Deny，该 connect() 会拿到 EPERM。
    Observed {
        sink: Arc<dyn NetEventSink>,
    },

    /// L7 可观测 + 域名 allowlist — 基于 slirp4netns 的用户态代理。
    /// DNS 查询、TLS SNI、HTTP Host 都会上报；不在 allow_hosts
    /// 白名单里的目标直接 RST。
    Gated {
        sink: Arc<dyn NetEventSink>,
        allow_hosts: Vec<HostPattern>,      // "pypi.org" / "*.githubusercontent.com"
        dns_policy: DnsPolicy,              // Resolver / PassThrough / Blocked
    },
}

pub enum HostPattern {
    Exact(String),          // "pypi.org"
    Suffix(String),         // "*.githubusercontent.com" → 存 ".githubusercontent.com"
    Cidr(ipnet::IpNet),     // 1.2.3.0/24
}

pub enum DnsPolicy {
    /// 代理自己递归解析（用你指定的上游 DNS）
    Resolver { upstream: Vec<SocketAddr> },
    /// 沙箱的 DNS 请求透传，仅记录
    PassThrough,
    /// 直接拒绝 DNS（强迫应用层用 IP）
    Blocked,
}

/// Sink 接收 NetEvent 并可返回判决。必须是 Send + Sync。
#[async_trait]
pub trait NetEventSink: Send + Sync {
    async fn on_event(&self, ev: &NetEvent) -> Verdict;
}

pub struct NetEvent {
    pub ts: SystemTime,
    pub pid: u32,
    pub comm: String,
    pub layer: Layer,               // L3 | L4 | L7_SNI | L7_HTTP | DNS
    pub protocol: Proto,            // Tcp | Udp | Icmp
    pub remote: Option<SocketAddr>,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub http_request_line: Option<(String, String)>,   // (method, path)
    pub dns_query: Option<String>,
    pub dns_answers: Vec<IpAddr>,
}

pub enum Verdict {
    Allow,
    Deny(&'static str),
}
```

使用示例：

```rust
let sink = Arc::new(MyLogger::new("/var/log/sandbox-net.log"));

let cfg = SandboxConfig::new(work)
    .network(NetworkPolicy::Gated {
        sink: sink.clone(),
        allow_hosts: vec![
            HostPattern::Exact("pypi.org".into()),
            HostPattern::Suffix("pythonhosted.org".into()),
            HostPattern::Suffix("githubusercontent.com".into()),
        ],
        dns_policy: DnsPolicy::Resolver {
            upstream: vec!["1.1.1.1:53".parse().unwrap()],
        },
    });

let out = tokimo_package_sandbox::run(&["pip", "install", "requests"], &cfg)?;
// sink 已经记录了:
//   DNS pypi.org → 151.101.1.223
//   TLS SNI pypi.org ALLOW
//   DNS files.pythonhosted.org → ... ALLOW
//   TLS SNI files.pythonhosted.org ALLOW
//   (任何对其它域名的访问 → DENY + 事件)
```

---

## 5. 实现路径

### Phase 1：`Observed` 档位（工作量：~1–2 周）

- 依赖：`aya`、`aya-ebpf`、cgroup v2 可用
- 步骤：
  1. 为每次 `run()` 创建独立 cgroup（`/sys/fs/cgroup/tokimo/sbx_<rand>/`）
  2. 用 `bwrap --init-pid-fd` 或通过 cgroup delegation，把 bwrap 子进程放进去
  3. 加载 eBPF 程序，attach 到 `cgroup/connect4/6` + `cgroup/sendmsg4/6`
  4. 用户态 aya 读 ring buffer，调用 `sink.on_event`
  5. 根据 sink verdict 通过 map 回写决策（或预先同步下发 allow list）

- 交付：对 `cargo run --example observed_pip` 能看到 pip 的每一次 connect

### Phase 2：`Gated` 档位（工作量：~2–4 周）

- 依赖：`slirp4netns`（二进制）、自家 proxy crate
- 步骤：
  1. 不用 `--unshare-net`，改为 `bwrap --userns --netns <fd>`，手动建 netns
  2. 在 netns 外启 slirp4netns，挂到 sandbox 的 TAP
  3. slirp4netns 的上游接口指向你的 Rust proxy socket
  4. proxy 实现：
     - DNS 协议解析（用 `trust-dns-proto`）
     - TLS ClientHello SNI 抽取（自写解析器，不需要 TLS 库）
     - HTTP/1.x 首行 + Host header 抽取
     - allowlist 匹配 + verdict
     - 命中允许则 socket 转发到真实上游
  5. 事件流推给 sink

### Phase 3：DNS 增强、HTTP/2 支持、MITM（可选，按需）

---

## 6. 可观测事件的使用方式

### 审计日志
```rust
struct FileSink(Mutex<File>);
#[async_trait]
impl NetEventSink for FileSink {
    async fn on_event(&self, ev: &NetEvent) -> Verdict {
        writeln!(self.0.lock().unwrap(), "{}", serde_json::to_string(ev).unwrap()).ok();
        Verdict::Allow
    }
}
```

### 实时告警
```rust
struct AlertSink { tx: mpsc::Sender<NetEvent> }
// 主程序订阅 rx，收到可疑事件（比如 IP 黑名单命中）立即停止沙箱
```

### 策略链
```rust
// Sink 本身可以组合多个策略
struct Chain(Vec<Arc<dyn NetEventSink>>);
#[async_trait]
impl NetEventSink for Chain {
    async fn on_event(&self, ev: &NetEvent) -> Verdict {
        for s in &self.0 {
            match s.on_event(ev).await {
                Verdict::Deny(r) => return Verdict::Deny(r),
                Verdict::Allow => {}
            }
        }
        Verdict::Allow
    }
}
```

---

## 7. 参考实现 / 可借鉴项目

| 项目 | 用来参考什么 |
|---|---|
| [Cilium Tetragon](https://github.com/cilium/tetragon) | 生产级 eBPF 运行时可观测性；cgroup/connect hooks 的大型实战 |
| [bcc/tcpconnect](https://github.com/iovisor/bcc) | 单文件示例，证明方案 1 全貌只需 ~100 行 eBPF C |
| [Aya](https://aya-rs.dev) | 纯 Rust eBPF 开发栈，无 libbpf 依赖 |
| [slirp4netns](https://github.com/rootless-containers/slirp4netns) | Podman rootless 模式的网络后端 |
| [passt / pasta](https://passt.top) | slirp4netns 的现代替代品，性能更好 |
| [mitmproxy](https://mitmproxy.org) | 方案 4 的参考实现，含 CA 注入逻辑 |
| [gVisor netstack](https://github.com/google/gvisor) | Google 的用户态 TCP/IP stack（Go 写的） |

---

## 8. 一句话总结

> 当前 `--unshare-net` 是**墙**，`--share-net` 是**无墙**。
> 要回答"谁在什么时候访问了什么"，需要"**窗**"：
> - L3/L4 的窗 = eBPF cgroup/connect（Phase 1，`Observed`）
> - L7 的窗 = slirp4netns + 用户态代理（Phase 2，`Gated`）
>
> 两者在 `NetworkPolicy` 里都是"枚举新增一档"的事，API 向后兼容，不影响现有 `Blocked` / `AllowAll` 用法。

---

## 9. 实现状态（实现笔记）

| 能力 | 状态 | 说明 |
|---|---|---|
| L7 HTTP / CONNECT 代理 | ✅ 已上 | `src/net_observer.rs`；`Observed` / `Gated` 自动注入 `HTTP_PROXY`。 |
| L4 seccomp-notify backend | ✅ 已上 rootless | `src/l4/seccomp_notify.rs`。在 `pre_exec` 里装 cBPF filter + `SECCOMP_FILTER_FLAG_NEW_LISTENER`，把 listener fd 通过 `SCM_RIGHTS` 送回宿主；宿主线程 `ioctl NOTIF_RECV`，`process_vm_readv` 读 `struct sockaddr` → `NetEvent { layer: L4 }`。Phase A = 观测语义；`Gated` 的 L4 deny 因为用户内存 TOCTOU 只能尽力而为。 |
| L4 seccomp-trace backend (fallback) | ✅ 已上 rootless | `src/l4/seccomp_trace.rs`。在 WSL2 / 容器等 `NEW_LISTENER` 返回 `EBUSY` 的场景下作为自动降级。cBPF filter 对 `connect` / `sendto` 返回 `SECCOMP_RET_TRACE | tag`，宿主 `PTRACE_SEIZE` 子进程 +`PTRACE_O_TRACESECCOMP|FORK|VFORK|CLONE|EXEC|EXITKILL`，tracer 线程 `waitpid(-1, __WALL)`；SECCOMP 事件触发 `PTRACE_GETEVENTMSG` 取 tag、`PTRACE_GETREGS` 取 sockaddr 指针、`process_vm_readv` 读取 → `NetEvent { layer: L4 }`。观测语义；deny 在这个后端里目前是 no-op（想 deny 需要 GETREGS/SETREGS 两段停 dance，暂不做）。 |
| L4 eBPF backend | 🧪 scaffold | `src/l4/ebpf.rs`（feature `ebpf`）。真正的 `cgroup/connect4/6` 程序需要独立 `tokimo-ebpf` crate + `bpf-linker`，且需要 root / `CAP_BPF`。 |
| L3 ICMP | ❌ 未规划 | |

### L4 后端自动降级

`NetworkPolicy::Observed{...}` / `Gated{...}` 启动时依次 `probe`：

1. **seccomp-notify**（首选）：fork 子进程尝试装 `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter。
2. **seccomp-trace**（fallback）：如果上面因为 `EBUSY` 失败，再 fork 子进程尝试普通 `SECCOMP_SET_MODE_FILTER`（无 flags）+ 宿主端同 UID `PTRACE_SEIZE`。WSL2 / 容器这条路通常都能用。
3. **L7-only**：两个都失败时，只留 L7 HTTP(S) 代理。不会让 sandbox 启动失败，只会 `tracing::warn!`。

验证方式：
```sh
cargo run --example l4_observer
```
该 example 在 sandbox 里跑 Python `socket.connect()`、`bash /dev/tcp/...`、
`nc -z`、`curl`；在能用 L4 的内核上，每个 `connect()` 会产生一条
`[... ] L4 <ip>:<port>` 事件，否则打印"zero L4 events"注记。

### 已知 L4 限制

- **WSL2 / 容器**：宿主进程通常继承了 seccomp filter，二次安装 `NEW_LISTENER`
  会返回 `EBUSY`。降级到 L7-only。
- **`notif.pid` 所在 pid namespace**：filter 安装在 bwrap 进入 pid ns 之前，
  所以 listener 看到的是**宿主** pid；`process_vm_readv` 按宿主 pid 读
  target task memory，需要 YAMA ptrace 允许同 UID（默认允许）。
- **TOCTOU**：`Gated` 模式下 L4 deny 不是一个可靠的安全边界，用户态可以在
  notify 回调返回前改写 sockaddr。enforcement 真要靠得住必须走 eBPF 或
  netfilter。
- **不 hook `sendmsg`**：我们自己用 `SCM_RIGHTS sendmsg` bootstrap
  listener fd，拦 `sendmsg` 会死锁。

### WSL2 EBUSY 专项诊断（2026 实测）

在 `5.15.153.1-microsoft-standard-WSL2` 上做了精确诊断，结论如下：

| 探测 | 结果 |
|---|---|
| `seccomp(SET_MODE_FILTER, 0, allow_prog)` —— 普通 filter 无 flags | ✅ 成功 |
| `seccomp(SET_MODE_FILTER, NEW_LISTENER, allow_prog)` | ❌ `EBUSY` |
| 先装普通 filter，再装 `NEW_LISTENER` | ❌ `EBUSY` |
| `unshare(CLONE_NEWUSER)` 后再装 `NEW_LISTENER` | ❌ `EBUSY` |
| `fork()` 后子进程装 `NEW_LISTENER` | ❌ `EBUSY` |

根因：WSL2 的早期 init 进程（`/proc/55707` 附近的 `MainThread`，一路
`Seccomp: 2, Seccomp_filters: 1` 下发）装了一个**带 notif 的** seccomp
filter。kernel 5.15 的 `has_listener()` 检查发现链上已经有 notif 存在，
就拒绝再次 `NEW_LISTENER` —— 不管你 fork / unshare / setuid 多少次都一样，
因为 seccomp filter 一旦挂上**永远不能卸载**，且所有 fork/exec 都继承。

**结论**：在 WSL2 这个实例里，**userspace 没有任何办法**让
seccomp-notify 后端跑起来。需要真 L4 观测请在以下环境跑：

- 真实 Linux VM（Hyper-V / QEMU / VirtualBox，不经过 WSL2 的 init）
- 物理 Linux 主机
- CI runner（GitHub Actions Ubuntu runner 实测可用）
- 远端 Linux dev container（真 `sshd`，不是 WSL interop）

**本机手动复现诊断**：
```sh
grep -E "Seccomp|NoNewPrivs" /proc/self/status
sysctl kernel.seccomp.actions_avail   # 看 user_notif 是否在列
# 写个最小 C：seccomp(SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...)
# 如果返回 EBUSY 就是被宿主 filter 挡住了
```

### 在 WSL2 本机怎么用

就按现在这样。`NetworkPolicy::Observed` / `Gated` 会：

1. 启 L7 HTTP(S) proxy —— **正常工作**，所有尊重 `HTTP_PROXY` 的客户端
   （`curl`、`wget`、`requests`、`urllib`、大部分 HTTP lib）都会被抓到。
2. 尝试起 L4 seccomp-notify backend —— probe 返回 `EBUSY`，打一条
   `tracing::info!("seccomp-notify unsupported ..., falling back to seccomp-trace")`
   然后继续。
3. 尝试起 L4 **seccomp-trace** backend —— 实测 WSL2 这条路能走通：
   `connect()` / `sendto()` 返回 `SECCOMP_RET_TRACE`，宿主 `PTRACE_SEIZE`
   抓住，走 `process_vm_readv` 读 `sockaddr` → L4 event。`bash /dev/tcp`、
   `nc`、`python socket.connect()` 都能看到。
4. 真 eBPF 需要 root + `CAP_BPF`，WSL2 默认没有，不可用。

`cargo run --example l4_observer` 会在同一次运行里同时验证 L4 + L7 事件。


