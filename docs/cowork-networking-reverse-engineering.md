# Cowork 网络逆向分析 & Rust 用户态网络方案

> 基于 IDA Pro 对 `cowork-svc.exe` (Go binary, `github.com/anthropics/cowork-win32-service v0.0.0-20260429`) 的逆向分析。
> smoltcp POC 已在 Windows 上验证通过 (TCP + UDP DNS)。
> 日期: 2026-05-02

## 1. Cowork 的网络架构 (逆向结论)

### 核心发现

Cowork **不使用 HCN NAT** 做 VM 出网。它用 `gvisor-tap-vsock v0.8.8` 实现了一个完全用户态的虚拟网络栈，通过 vsock 隧道转发 VM 流量。

```
┌─────────────────────────────────────────────────────────────────┐
│  tokimo (当前)                                                   │
│                                                                 │
│  VM ──HCS NIC──▶ HCN vSwitch ──VFP SNAT──▶ 主机 IP 转发 ──▶ WAN │
│                                               ^^^^^^^^^^^^^^^^ │
│                                               需要 Forwarding=Enabled │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  cowork                                                         │
│                                                                 │
│  VM ──vsock──▶ 服务进程 ──gvisor netstack──▶ Go net.Dial() ──▶ WAN │
│                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    │
│                  用户态 TCP/IP 栈，普通 socket，无需 IP 转发       │
└─────────────────────────────────────────────────────────────────┘
```

### IDA 证据链

| 地址 | 函数/字符串 | 含义 |
|---|---|---|
| `0x89bd40` | `NewVirtualNetworkProvider` | 创建 gvisor-tap-vsock 虚拟网络 |
| `0x89bee1` | 调用 `containers/gvisor-tap-vsock/pkg/virtualnetwork.New` | 初始化 netstack |
| `0x89c0c0` | `VirtualNetworkProvider.Start` | 在 vsock 端口上监听 VM 连接 |
| `0x89c182` | 调用 `NewHVSocketListener` | 创建 AF_HYPERV 监听器 |
| `0x89c580` | `acceptLoop` | 接受 VM vsock 连接，分发 goroutine |
| `0xa890e9` | `"172.16.10.0/24"` | 用户态网络子网 |
| `0xa8ffc5` | `"cowork-vm-vnet"` | HCN 网络名 (仅用于清理旧网络) |
| `0x972162` | `gvisor-tap-vsock/pkg/services/dhcp` | 内置 DHCP 服务 |
| `0x971c74` | `gvisor-tap-vsock/pkg/services/dns` | 内置 DNS 代理 |
| `0x9736e1` | `gvisor-tap-vsock/pkg/services/forwarder` | TCP/UDP 转发器 |

### 关键配置 (从 `NewVirtualNetworkProvider` 反编译)

```go
config := &types.Configuration{
    MTU:               1400,
    Subnet:            "172.16.10.0/24",
    GatewayIP:         "172.16.10.1",       // 11 chars
    GatewayMacAddress: "7e:b3:a1:d6:42:f0",
    Protocol:          "tcp",               // 4 chars
    DHCPStaticLeases:  map[string]string{...},
    NAT:               map[string]string{...},
    GatewayVirtualIPs: []string{...},
}
vn := virtualnetwork.New(config)
```

### HCN 函数加载但从未调用

`HcnCreateNetwork` (qword_FC6BB8) 和 `HcnCreateEndpoint` (qword_FC6BE0) 仅在 `InitHCN` 中加载为 `LazyProc`，xref 分析显示**无任何调用点**。HCN 仅用于 `cleanupLegacyHCNNetworks` 删除旧网络。

### 为什么 cowork 不需要 `Forwarding=Enabled`

VM 的 TCP 流量路径:

```
1. Guest app → kernel TCP → virtio-net → vsock
2. vsock → 服务进程 AF_HYPERV accept()
3. gvisor netstack 解析以太网帧/IP包/TCP段
4. netstack 发起 host-side socket: net.Dial("tcp", target)
5. Go runtime 使用主机正常 socket API 发送
6. 回程: host recv → netstack 封装 → vsock → guest
```

步骤 4-5 是**普通的出站 socket 连接**，与用户运行 `curl` 一样。不需要 IP 转发，因为流量不是从一个接口路由到另一个接口，而是由进程读取后重新发起连接。

---

## 2. Rust smoltcp POC — 已验证

### 2.1 验证结果

`examples/smoltcp_netstack.rs` 在 Windows 上跑通了 TCP + UDP 全链路:

```
=== smoltcp userspace network stack POC ===
Subnet: 192.168.127.0/24
VM: 192.168.127.2 ↔ Host: 192.168.127.1
Transport: in-memory channel (simulates vsock)

── Test 1: TCP (HTTP GET → 1.1.1.1:80) ──
[Host] TCP listening on :80, UDP listening on :53
[VM/TCP] Sending HTTP request (52 bytes)
[Host/TCP] Got request (52 bytes)
[Host/TCP] Got 381 bytes from upstream
[Host/TCP] Response sent back
[VM/TCP] OK — HTTP/1.1 301 Moved Permanently (Cloudflare)

── Test 2: UDP (DNS query → example.com) ──
[VM/UDP] Sending DNS query for example.com (29 bytes)
[Host/UDP] DNS query from 192.168.127.2:54321 (29 bytes)
[Host/UDP] DNS response from 1.1.1.1 (61 bytes)
[VM/UDP] Got DNS response (61 bytes)
[VM/UDP] OK — example.com resolves to 104.20.23.154

=== All tests complete ===
```

### 2.2 POC 架构

```
VM thread (192.168.127.2)              Host thread (192.168.127.1)
┌──────────────────────┐              ┌──────────────────────────┐
│ smoltcp::Interface   │              │ smoltcp::Interface       │
│   TCP client socket  │  channel     │   TCP listen :80         │
│   UDP socket :54321  │ ─(frames)─► │   UDP listen :53         │
│                      │              │                          │
│ ChannelDevice        │              │ ChannelDevice            │
│  rx: chan::Receiver  │              │  rx: chan::Receiver      │
│  tx: chan::Sender    │ ◄─(frames)── │  tx: chan::Sender        │
└──────────────────────┘              └──────┬───────────────────┘
                                             │
                                    ┌────────▼────────┐
                                    │ TcpStream       │ → 1.1.1.1:80
                                    │ UdpSocket       │ → 1.1.1.1:53
                                    │ (普通 host socket)│
                                    └─────────────────┘
```

关键组件:
- **`ChannelDevice`**: 实现 smoltcp `Device` trait，backed by crossbeam channel。可直接替换为 vsock 的 `Read`/`Write` wrapper。
- **Host 侧**: smoltcp TCP listen socket 接受连接后，以 `std::net::TcpStream` 发起真实连接。UDP 同理。
- **Guest 侧**: smoltcp TCP/UDP socket 直接使用，底层自动封装为以太网帧。

### 2.3 smoltcp API 要点 (从 POC 验证)

```toml
# Cargo.toml (已添加到 [dev-dependencies])
smoltcp = { version = "0.13", default-features = false, features = [
    "std", "medium-ethernet", "proto-ipv4", "socket-tcp", "socket-udp",
] }
crossbeam-channel = "0.5"
```

smoltcp 0.13 关键 API:

```rust
// Device trait — 读写以太网帧
impl Device for ChannelDevice {
    type RxToken<'a> = ChanRxToken;
    type TxToken<'a> = ChanTxToken;
    fn receive(&mut self, _ts: Instant) -> Option<(RxToken, TxToken)>;
    fn transmit(&mut self, _ts: Instant) -> Option<TxToken>;
}

// TCP connect — local endpoint 传 u16 (端口号)，smoltcp 自动选择源地址
socket.connect(iface.context(), remote_endpoint, local_port_u16)?;

// TCP recv — closure 返回 (R, usize)，recv 返回 Result<R, _>
let data = socket.recv(|b| (b.to_vec(), b.len()))?;

// UDP recv — 返回引用，需 .to_vec() 拷贝
let (data, src) = socket.recv()?;
socket.send_slice(&response, src)?;

// 路由 — 必须设置才能访问非直连子网
iface.routes_mut().add_default_ipv4_route(gateway)?;

// 事件循环 — poll 驱动收发，需要频繁调用
iface.poll(smoltcp_now(), &mut device, &mut sockets);
```

### 2.4 从 POC 到生产集成

将 `ChannelDevice` 替换为 vsock 设备:

```rust
struct VsockDevice {
    reader: Box<dyn Read + Send>,   // HvSock 或 AF_VSOCK 的 read half
    writer: Box<dyn Write + Send>,  // HvSock 或 AF_VSOCK 的 write half
}

impl Device for VsockDevice {
    fn receive(&mut self, _ts: Instant) -> Option<(VsockRx, VsockTx)> {
        // 从 vsock 读取长度前缀的以太网帧
        let mut hdr = [0u8; 4];
        self.reader.read_exact(&mut hdr).ok()?;
        let len = u32::from_be_bytes(hdr) as usize;
        let mut frame = vec![0u8; len];
        self.reader.read_exact(&mut frame).ok()?;
        Some((VsockRx(frame), VsockTx(&mut self.writer)))
    }
    // ...
}
```

---

## 3. 集成方案

### 3.1 两条路径

| 路径 | 条件 | 网络方式 |
|---|---|---|
| HCN (现有) | 主机 WAN NIC `Forwarding=Enabled` | 内核 NAT，性能最好 |
| smoltcp (新增) | 默认 fallback | 用户态栈，无需 IP 转发 |

`handle_start_vm` 中先尝试 HCN，失败则 fallback 到 smoltcp:

```rust
let (ep_id, ep_mac, use_smoltcp) = match cfg.network {
    NetworkPolicy::Blocked => (None, None, false),
    NetworkPolicy::AllowAll => {
        match hcn::HcnNetwork::create_or_open_nat() {
            Ok(net) => match net.create_endpoint() {
                Ok(ep) => (Some(ep.id_string()), Some(ep.mac_string().to_string()), false),
                Err(_) => (None, None, true),  // fallback
            },
            Err(_) => (None, None, true),  // fallback
        }
    }
};
```

### 3.2 Guest 侧集成

Guest init 在 `AllowAll + smoltcp` 模式下启动 TUN 设备:

```bash
# init.sh 或 init 在 AllowAll 模式下执行:
ip tuntap add dev tun0 mode tun
ip addr add 192.168.127.2/24 dev tun0
ip link set tun0 up
ip route add default via 192.168.127.1 dev tun0
# 然后读写 /dev/net/tun，帧通过 vsock 发送
```

或者更简单：Guest 侧用 SOCKS5 代理 (不需要 TUN 设备):

```bash
# init 启动本地 SOCKS5 代理，通过 vsock 隧道转发
export ALL_PROXY=socks5://127.0.0.1:1080
```

### 3.3 文件清单

| 动作 | 文件 | 说明 |
|---|---|---|
| 已有 | `examples/smoltcp_netstack.rs` | POC 验证 (TCP + UDP) |
| 新增 | `src/bin/tokimo-sandbox-svc/imp/netstack.rs` | Host 侧 smoltcp 网络栈 |
| 修改 | `src/bin/tokimo-sandbox-svc/imp/mod.rs` | HCN fallback 到 smoltcp |
| 修改 | `src/bin/tokimo-sandbox-svc/imp/vmconfig.rs` | smoltcp 模式不加 NetworkAdapters |
| 修改 | `src/bin/tokimo-sandbox-init/main.rs` | TUN 或 SOCKS5 启动 |
| 修改 | `Cargo.toml` | 添加 smoltcp 依赖 |

---

## 4. 结论

| 维度 | 保持 HCN | smoltcp 用户态栈 |
|---|---|---|
| 解决 Forwarding 问题 | 否 | **是 (POC 验证)** |
| TCP | 内核 NAT | **用户态代理 (POC 验证)** |
| UDP/DNS | 内核 NAT | **用户态代理 (POC 验证)** |
| 包检查能力 | 无 | 可扩展 (Observed/Gated) |
| 新增依赖 | 无 | smoltcp 0.13 ~100KB |
| 与 cowork 对齐 | 否 | **完全对齐** |
