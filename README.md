# Hybrid Heterogeneous P2P Overlay Network (`p2p-overlay-net`)

一套基于 **“1 台不稳定中心引导服务器 (Lighthouse) + 浏览器边缘节点 (Browser Peer) + 后端超级节点 (Native Peer) 混合自治组网 + 无序 WebRTC/UDP 承载自研 20 字节路由头与调优版 KCP/E2EE”** 的完整工程实现。

---

## 核心特性与架构对齐

1. **死守 1200 Bytes MTU 红线（零分片）**：
   - 外层固定 **20 Bytes Overlay 虚拟路由头**（`Magic: 0xA5`、`Ver: 4b`、`PacketType: 4b`、`TTL: 8b`、`Flags: 8b`、`SrcNodeID: 64b`、`DstNodeID: 64b`）。
   - 内层 **16 Bytes E2EE 认证标签** + **24 Bytes KCP 帧头** + **最大 1140 Bytes 业务分片 (MSS)**，单包严格 `<= 1200 Bytes`。
2. **极简调用接口**：
   - **Browser 端**：`const c = await peer.connect(targetNodeId); c.send("hello");`
   - **Native (Go) 端**：`lc, _ := native.Listen(cfg); conn, _ := lc.Accept()`（兼容标准 `net.Conn` 的 `Read`/`Write`/`Close`）。
3. **0-RTT 无感中继与后台静默打洞热切换（Seamless Path Upgrade）**：
   - 两个未直连节点调用 `connect(id)` 后 **0 毫秒等待**，首个 KCP 数据包立即通过任意已连接的 Native Peer 超级节点无状态零拷贝转发（`Via Relay`）。
   - 同时后台自动触发带内信令（`PacketType = 0x3 SIGNALING`，剔除音视频冗余字段并 Deflate 压缩 SDP），打洞成功后路由表原子级切换为 `Direct DataChannel / Direct UDP`，上层 KCP 会话不断连、不丢包。
4. **中心服务器零流量负担与抗掉线**：
   - `cmd/lighthouse` 仅提供初始种子节点列表（Seed Candidates）、冷启动握手转发与轻量级 UDP STUN 反射服务（RFC 5389），**绝不转发任何业务数据包**。一旦节点连上任意 1 台超级节点，即便中心服务器宕机，全网依然通过带内信令自治组网。
5. **多线程与浏览器 Web Worker 深度优化**：
   - **Browser 端**：将 KCP 状态机、E2EE 加解密、20B 路由解析与 **三级 SCTP `bufferedAmount` 背压阀门**（`0KB` 极速模式 / `<=64KB` 温和降速模式 / `>64KB` 熔断挂起模式）完全放入独立 `Web Worker` (`web-sdk/p2p-worker.js`)，支持 `RTCDataChannel` Transferable 控制权移交与“收包事件 + 10ms 定时器混合驱动”（防御后台标签页休眠限频）。
   - **Native (Go) 端**：采用按 `SrcNodeID` 哈希分片的多协程 Worker Pool + `sync.Pool` 1200B 报文池零分配复用 + 原地修包（`DecrementTTLInPlace`）+ 32 分片无锁化令牌桶限流器（限制单叶子节点最高 `500 KB/s` 中继带宽）。

---

## 目录结构

```text
p2p-overlay-net/
├── .github/workflows/
│   └── ci-release.yml          # GitHub Actions: Go 单元测试、JS 校验、多平台交叉编译、Wasm 构建与 Release 打包
├── cmd/
│   ├── lighthouse/main.go      # 灯塔服务器 (WebSocket 种子发现 + 冷启动信令 + 轻量 UDP STUN 服务)
│   ├── native-peer/main.go     # Go Native 超级节点 CLI 示例 (演示 lc = Listen() 与 conn = lc.Accept())
│   └── wasm-core/main.go       # Go Sans-IO 协议核心编译为 WebAssembly 入口
├── pkg/
│   ├── overlay/
│   │   ├── header.go           # 20B 路由头编解码、原地 TTL 递减、Ed25519 -> 64-bit Crypto-ID
│   │   ├── kcp.go              # Sans-IO 调优版 KCP (1140B MSS, 快速重传, 三级背压阀门联动)
│   │   ├── crypto.go           # ChaCha20-Poly1305 / X25519 E2EE 端到端加密与 SDP Deflate 压缩
│   │   ├── ratelimit.go        # 32 分片 Token Bucket 令牌桶限速器 (默认 500 KB/s 防带宽耗尽)
│   │   ├── router.go           # 0-RTT 中继转直连状态机、带内 SIGNALING 路由与 Gossip
│   │   └── overlay_test.go     # 核心协议栈完整单元测试
│   └── native/
│       └── node.go             # Native Peer SDK: 多协程 Worker Pool、sync.Pool、Raw UDP + WebRTC 适配器
├── web-sdk/
│   ├── kcp-engine.js           # 浏览器端 Sans-IO 20B 路由头 + KCP + E2EE + 三级背压引擎
│   ├── p2p-worker.js           # 独立 Web Worker 守护线程 (RTCDataChannel 接管 + 混合时钟驱动)
│   ├── p2p-client.js           # 极简前端 SDK: const c = await peer.connect(id)
│   ├── index.html              # 可视化双节点 0-RTT 中继与热切换直连测试面板
│   └── test-kcp-node.js        # Node.js 自动化协议栈自检脚本
├── docs/
│   └── ARCHITECTURE.md         # 完整架构设计与工程实施计划书
├── Makefile
└── go.mod
```

---

## 快速上手指南

### 1. 启动灯塔引导服务 (Lighthouse)
```bash
go run ./cmd/lighthouse -http :8080 -stun :3478 -web ./web-sdk
```
- WebSocket 引导与种子发现：`ws://127.0.0.1:8080/ws`
- HTTP 种子候选查询：`http://127.0.0.1:8080/api/seeds`
- 轻量级 STUN 服务：`udp://127.0.0.1:3478`
- 浏览器测试面板：打开 `http://127.0.0.1:8080/`

### 2. Native Peer 极简编程示例 (`lc = accept()`)
```go
package main

import (
    "log"
    "github.com/p2p-overlay-net/overlay/pkg/native"
)

func main() {
    // 启动超级节点：自动开启多核分片 Worker Pool、Raw UDP 监听、0-RTT 中继与灯塔注册
    lc, err := native.Listen(native.Config{
        LighthouseURL: "ws://127.0.0.1:8080/ws",
        UDPListenAddr: ":9000",
        IsSuperNode:   true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer lc.Close()

    // 如同标准库 net.Listener 一样简单地接收可靠 KCP 连接
    for {
        conn, err := lc.Accept()
        if err != nil {
            break
        }
        go func(c *native.Conn) {
            defer c.Close()
            buf := make([]byte, 2048)
            n, _ := c.Read(buf)
            _, _ = c.Write(buf[:n]) // 原样回显 (自动经由 KCP + E2EE 传输)
        }(conn)
    }
}
```

### 3. Browser 端极简编程示例 (`c = await peer.connect(id)`)
```javascript
import { BrowserOverlayPeer } from "./web-sdk/p2p-client.js";

const peer = new BrowserOverlayPeer({
  lighthouseUrl: "ws://127.0.0.1:8080/ws",
  workerUrl: "./web-sdk/p2p-worker.js",
});

// 0-RTT 建连：先走超级节点无状态包转发，后台静默交换压缩 SDP 打洞并无感切换至直连 WebRTC
const c = await peer.connect("bbbb000000000002");

c.onMessage((evt) => {
  console.log("收到消息:", evt.text(), "是否经由中继:", evt.relayed);
});

c.send("Hello over Unordered WebRTC + KCP!");
```
