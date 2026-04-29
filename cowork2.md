## 沙箱通讯架构完整总结

---

### 一、整体拓扑

```
用户本机 (Windows)
  │
  ├─ virtiofsd ──→ 文件共享（不走网络）
  │
  └─ Linux VM (Ubuntu 22)
       │
       ├─ /mnt/.virtiofs-root/shared/... ← virtiofs FUSE 挂载
       │
       └─ Bubblewrap 沙箱 (PID 1)
            │
            ├─ PID namespace 隔离 (仅 7 进程可见)
            ├─ Network namespace 隔离 (仅 lo 可用)
            │
            ├─ [文件通道] bind-mount virtiofs 子目录
            │
            └─ [网络通道] socat TCP→Unix Socket→宿主机代理
```

---

### 二、启动命令（bwrap PID 1 完整参数）

| 参数 | 功能 |
|------|------|
| `--new-session` | 创建新会话 |
| `--die-with-parent` | 父进程退出时自杀 |
| `--unshare-net` | 隔离网络命名空间 |
| `--unshare-pid` | 隔离 PID 命名空间 |
| `--bind /tmp/claude-http-{id}.sock ...` | 注入 HTTP 代理 socket |
| `--bind /tmp/claude-socks-{id}.sock ...` | 注入 SOCKS 代理 socket |
| `--setenv HTTP_PROXY=http://localhost:3128` 等 | 注入代理环境变量 |
| `--ro-bind / /` | 只读挂载根文件系统 |
| `--bind / /` | 可写覆盖 |
| `--tmpfs /etc/ssh/ssh_config.d` | 隔离 SSH 配置 |
| `--dev /dev` | 挂载设备 |
| `--proc /proc` | 挂载 proc |

启动后执行的 bash 脚本：

```bash
socat TCP-LISTEN:3128,fork,reuseaddr \
  UNIX-CONNECT:/tmp/claude-http-{id}.sock >/dev/null 2>&1 &

socat TCP-LISTEN:1080,fork,reuseaddr \
  UNIX-CONNECT:/tmp/claude-socks-{id}.sock >/dev/null 2>&1 &

trap "kill %1 %2 2>/dev/null; exit" EXIT

bash -c '<用户命令>'
```

---

### 三、网络代理链路（唯一出站通道）

```
沙箱内程序
  │
  ├─ HTTP/HTTPS ──→ http://localhost:3128  (socat PID 3, TCP LISTEN)
  │                      │
  │                      └──→ /tmp/claude-http-{id}.sock  (Unix Domain Socket)
  │                                │
  │                                └──→ 宿主机监听端 → 互联网
  │
  └─ SOCKS/其他 ──→ socks5h://localhost:1080  (socat PID 4, TCP LISTEN)
                         │
                         └──→ /tmp/claude-socks-{id}.sock  (Unix Domain Socket)
                                   │
                                   └──→ 宿主机监听端 → 互联网
```

**验证**：curl 请求经过代理链路后返回 `Connection blocked by network allowlist`，证实链路通畅，仅在宿主机侧被白名单拦截。

**完整代理环境变量**（20 个）：

| 变量 | 值 | 覆盖协议 |
|------|-----|---------|
| `HTTP_PROXY` / `http_proxy` | `http://localhost:3128` | HTTP |
| `HTTPS_PROXY` / `https_proxy` | `http://localhost:3128` | HTTPS |
| `ALL_PROXY` / `all_proxy` | `socks5h://localhost:1080` | 所有 TCP |
| `GRPC_PROXY` / `grpc_proxy` | `socks5h://localhost:1080` | gRPC |
| `FTP_PROXY` / `ftp_proxy` | `socks5h://localhost:1080` | FTP |
| `RSYNC_PROXY` | `localhost:1080` | rsync |
| `DOCKER_HTTP_PROXY` | `http://localhost:3128` | Docker |
| `DOCKER_HTTPS_PROXY` | `http://localhost:3128` | Docker |
| `CLOUDSDK_PROXY_TYPE` | `https` | gcloud |
| `CLOUDSDK_PROXY_ADDRESS` | `localhost` | gcloud |
| `CLOUDSDK_PROXY_PORT` | `3128` | gcloud |
| `GIT_SSH_COMMAND` | `ssh -o ProxyCommand='socat - PROXY:localhost:%h:%p,proxyport=3128'` | Git SSH |
| `NO_PROXY` / `no_proxy` | `localhost,127.0.0.1,...` | 排除列表 |

---

### 四、文件共享通道（virtiofs FUSE）

不走网络，通过 virtiofs 守护进程直接在 VM 和宿主机间共享文件：

| 沙箱内挂载点 | 宿主机路径 | 权限 | 用途 |
|-------------|-----------|------|------|
| `mnt/outputs` | `.../local_.../outputs` | rw | 工作输出 |
| `mnt/uploads` | `.../local_.../uploads` | ro | 用户上传 |
| `mnt/.auto-memory` | `.../memory/memory` | ro | 持久记忆 |
| `mnt/.claude/projects` | `.../local_.../projects` | ro | 项目配置 |
| `mnt/.claude/skills` | `.../skills-plugin/.../skills` | ro | 技能文件 |

所有挂载类型均为 `fuse`，后端存储为 `/mnt/.virtiofs-root/shared/`。

---

### 五、运行时全景

```
进程树 (PID namespace 内，共 7 个进程)：

PID 1  bwrap         ← 容器主进程，sleep 等待
PID 2  bash          ← 启动脚本，管理 socat 生命周期
PID 3  socat         ← TCP:3128 ↔ claude-http-{id}.sock
PID 4  socat         ← TCP:1080 ↔ claude-socks-{id}.sock

cgroup: 0::/coworkd/oneshot-{uuid}
```

**可见网络接口**：仅 `lo`（loopback），`tap0` 在 sysfs 可见但 netlink 不可达。

---

### 六、关键设计特点

1. **双重隔离**：PID + Network 命名空间独立，沙箱内看不到宿主机进程和网络
2. **强制代理**：网络隔离后唯一出路是 Unix socket 隧道，所有流量可审计/过滤
3. **协议分离**：HTTP/HTTPS 走 3128（HTTP CONNECT），其他协议走 1080（SOCKS5h），SOCKS5h 的 `h` 后缀意味着 DNS 解析在代理端完成，防止 DNS 泄露
4. **文件不走网络**：virtiofs 是内核级 FUSE 共享，零网络开销
5. **一次性**：每次 bash 调用生成新的 socket ID，会话结束容器销毁（`--die-with-parent`）