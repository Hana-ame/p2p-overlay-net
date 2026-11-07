# 混合异构 P2P 自治覆盖网络（Overlay Network）架构设计与工程实施蓝图

本文档对应代码仓库的完整工程设计规范，涵盖三类异构节点分工、20 字节固定路由头、1200 Bytes MTU 红线、0-RTT 先中继后打洞无感热切换机制、以及浏览器 Web Worker 三级 SCTP 背压阀门控制。

## 1. 字节级报文规范（1200 Bytes MTU 红线）

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Magic (0xA5) | Ver(4)|Type(4)|      TTL      |     Flags     |  (4 Bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source NodeID                         |
|                           (64-bit)                            |  (8 Bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Destination NodeID                      |
|                           (64-bit)                            |  (8 Bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload (Max 1180 Bytes)                  |
|         (24B KCP Header + 16B E2EE Tag + Max 1140B Data)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **外层路由头**：固定 `20 Bytes`（`pkg/overlay/header.go` & `web-sdk/kcp-engine.js`）。
- **Native Peer 零拷贝转发**：调用 `overlay.DecrementTTLInPlace(rawPacket)` 原地递减 `TTL` 并置位 `FlagRelayed`，直接写入下一跳 `UDP` 或 `RTCDataChannel`，不拷贝载荷、不解密内部数据。
- **三级背压阀门**：在 `web-sdk/kcp-engine.js` 与 `pkg/overlay/kcp.go` 中实现：
  - `bufferedAmount === 0`：极速模式（开启 Fast Retransmit）。
  - `0 < bufferedAmount <= 64 KB`：温和模式（关闭快速重传，RTO 乘数放大 `1.5x`）。
  - `bufferedAmount > 64 KB`：熔断模式（挂起 KCP 重传计时器，抛出 `onBackpressure` 暂停新数据写入，待 `bufferedamountlow` 触发后恢复）。
