/**
 * @fileoverview Dedicated Web Worker hosting the Overlay Routing Table, 0-RTT Relay -> Direct
 * Seamless Path Upgrade state machine, E2EE ChaCha20/Stream session, and KCP ARQ with
 * 3-Level SCTP Backpressure Valve.
 *
 * Why a Web Worker?
 *   1. Keeps KCP timers (10ms tick) immune to main-thread UI jank and mitigates background tab throttling.
 *   2. Accepts transferred `RTCDataChannel` instances directly via `postMessage(msg, [dc])`
 *      (where supported by Chromium/modern browsers) or zero-copy `ArrayBuffer` transfers.
 */

import {
  PacketType,
  HeaderFlags,
  BackpressureMode,
  encodeOverlayPacket,
  decodeOverlayPacket,
  toNodeIdBigInt,
  formatNodeIdHex,
  compactSignalingSDP,
  ZeroRTTE2EE,
  KCPConnection,
} from "./kcp-engine.js";

let selfNodeId = "0000000000000001";
let defaultRelayPeerId = null;

/** @type {Map<string, {dc?: RTCDataChannel, port?: MessagePort, bufferedAmount: number, type: 'direct'|'relay'}>} */
const links = new Map();

/** @type {Map<string, {kcp: KCPConnection, e2ee: ZeroRTTE2EE, punchRequested: boolean, pathMode: 'relay'|'direct'}>} */
const sessions = new Map();

const startEpoch = performance.now();
function nowMs() {
  return Math.floor(performance.now() - startEpoch) >>> 0;
}

function getOrCreateSession(remoteNodeId) {
  const normId = formatNodeIdHex(toNodeIdBigInt(remoteNodeId));
  let sess = sessions.get(normId);
  if (sess) return sess;

  const conv = Number((toNodeIdBigInt(selfNodeId) ^ toNodeIdBigInt(normId)) & 0x7fffffffn) || 1;
  const e2ee = new ZeroRTTE2EE(selfNodeId, normId);

  const kcp = new KCPConnection(
    conv,
    (kcpFrame) => {
      sendOverlayKCPFrame(normId, sess, kcpFrame);
    },
    (paused, mode) => {
      self.postMessage({
        type: "backpressure",
        peerId: normId,
        paused,
        mode,
      });
    }
  );

  sess = {
    peerId: normId,
    kcp,
    e2ee,
    punchRequested: false,
    pathMode: links.has(normId) ? "direct" : "relay",
  };
  sessions.set(normId, sess);
  return sess;
}

/**
 * 0-RTT Seamless Path Selection:
 *   1. If a direct WebRTC DataChannel to `dstPeerId` is open, send directly.
 *   2. Otherwise, immediately send via `defaultRelayPeerId` (0ms wait!) and trigger
 *      a background in-band SDP hole-punch request on the first packet.
 */
function selectLinkForPeer(dstPeerId, sess) {
  const direct = links.get(dstPeerId);
  if (direct) {
    if (sess && sess.pathMode !== "direct") {
      sess.pathMode = "direct";
      self.postMessage({ type: "path-upgraded", peerId: dstPeerId, mode: "direct" });
    }
    return direct;
  }

  if (sess && !sess.punchRequested && dstPeerId !== selfNodeId) {
    sess.punchRequested = true;
    self.postMessage({
      type: "request-hole-punch",
      targetPeerId: dstPeerId,
    });
  }

  if (defaultRelayPeerId && links.has(defaultRelayPeerId)) {
    return links.get(defaultRelayPeerId);
  }
  // Fallback to any active link
  for (const link of links.values()) {
    return link;
  }
  return null;
}

function sendOverlayKCPFrame(dstPeerId, sess, kcpFrame) {
  const link = selectLinkForPeer(dstPeerId, sess);
  if (!link) return;

  // Enforce 3-Level Browser SCTP Backpressure Valve before dc.send()
  const buffered = link.dc ? link.dc.bufferedAmount : link.bufferedAmount || 0;
  const mode = sess.kcp.updateBackpressure(buffered);
  if (mode === BackpressureMode.CIRCUIT) {
    return; // Suspend sending while bufferedAmount > 64KB
  }

  const cipherPayload = sess.e2ee.seal(kcpFrame);
  const packet = encodeOverlayPacket(
    {
      srcNodeId: selfNodeId,
      dstNodeId: dstPeerId,
      type: PacketType.KCP_DATA,
      flags: HeaderFlags.ENCRYPTED,
    },
    cipherPayload
  );
  transmitRawOnLink(link, packet);
}

function transmitRawOnLink(link, packetBytes) {
  if (link.dc && link.dc.readyState === "open") {
    link.dc.send(packetBytes);
  } else if (link.port) {
    const copy = packetBytes.slice();
    link.port.postMessage({ type: "raw-tx", buffer: copy.buffer }, [copy.buffer]);
  } else {
    const copy = packetBytes.slice();
    self.postMessage({ type: "raw-tx", peerId: link.peerId, buffer: copy.buffer }, [copy.buffer]);
  }
}

function handleInboundRawPacket(rawBuffer, fromLinkPeerId) {
  let decoded;
  try {
    decoded = decodeOverlayPacket(rawBuffer);
  } catch (_) {
    return;
  }

  // Leaf node rule: Browser Peer NEVER relays packets for other nodes
  if (decoded.dstNodeId !== selfNodeId) {
    return;
  }

  const srcPeerId = decoded.srcNodeId;

  switch (decoded.type) {
    case PacketType.KCP_DATA: {
      const sess = getOrCreateSession(srcPeerId);
      try {
        const plainKcp = sess.e2ee.open(decoded.payload);
        // Event-driven + timer hybrid: input() immediately flushes ACKs
        sess.kcp.input(plainKcp, nowMs());
        let msg;
        while ((msg = sess.kcp.recv()) !== null) {
          self.postMessage(
            {
              type: "kcp-recv",
              peerId: srcPeerId,
              payload: msg.buffer,
              relayed: (decoded.flags & HeaderFlags.RELAYED) !== 0,
            },
            [msg.buffer]
          );
        }
      } catch (err) {
        // Ignore tampered / invalid E2EE frames
      }
      break;
    }

    case PacketType.UNRELIABLE_DATA: {
      const copy = decoded.payload.slice();
      self.postMessage(
        {
          type: "unreliable-recv",
          peerId: srcPeerId,
          payload: copy.buffer,
        },
        [copy.buffer]
      );
      break;
    }

    case PacketType.SIGNALING: {
      const text = new TextDecoder().decode(decoded.payload);
      try {
        const sig = JSON.parse(text);
        self.postMessage({
          type: "inband-signaling",
          fromPeerId: srcPeerId,
          signal: sig,
        });
      } catch (_) {}
      break;
    }

    case PacketType.PING_PONG: {
      if ((decoded.flags & HeaderFlags.PONG) === 0) {
        const link = links.get(fromLinkPeerId) || selectLinkForPeer(srcPeerId, null);
        if (link) {
          const pong = encodeOverlayPacket(
            {
              srcNodeId: selfNodeId,
              dstNodeId: srcPeerId,
              type: PacketType.PING_PONG,
              flags: HeaderFlags.PONG,
            },
            decoded.payload
          );
          transmitRawOnLink(link, pong);
        }
      }
      break;
    }
  }
}

function bindTransferredDataChannel(peerId, dc, isRelay) {
  dc.binaryType = "arraybuffer";
  dc.bufferedAmountLowThreshold = 16 * 1024; // 16 KB recovery threshold

  const linkEntry = {
    peerId,
    dc,
    bufferedAmount: 0,
    type: isRelay ? "relay" : "direct",
  };
  links.set(peerId, linkEntry);
  if (isRelay || !defaultRelayPeerId) {
    defaultRelayPeerId = peerId;
  }

  dc.onbufferedamountlow = () => {
    const sess = sessions.get(peerId);
    if (sess) {
      sess.kcp.updateBackpressure(dc.bufferedAmount);
      sess.kcp.flush();
    }
  };

  dc.onmessage = (ev) => {
    handleInboundRawPacket(ev.data, peerId);
  };

  dc.onclose = () => {
    links.delete(peerId);
  };

  if (!isRelay && sessions.has(peerId)) {
    const sess = sessions.get(peerId);
    sess.pathMode = "direct";
    self.postMessage({ type: "path-upgraded", peerId, mode: "direct" });
  }
}

self.onmessage = (ev) => {
  const data = ev.data;
  if (!data || !data.type) return;

  switch (data.type) {
    case "init": {
      selfNodeId = formatNodeIdHex(toNodeIdBigInt(data.nodeId));
      self.postMessage({ type: "ready", nodeId: selfNodeId });
      break;
    }

    case "attach-datachannel": {
      const peerId = formatNodeIdHex(toNodeIdBigInt(data.peerId));
      if (data.channel) {
        // Direct Transferable RTCDataChannel inside Worker
        bindTransferredDataChannel(peerId, data.channel, Boolean(data.isRelay));
      } else {
        // Fallback proxy link if browser does not support transferable RTCDataChannel
        links.set(peerId, {
          peerId,
          bufferedAmount: 0,
          type: data.isRelay ? "relay" : "direct",
        });
        if (data.isRelay || !defaultRelayPeerId) {
          defaultRelayPeerId = peerId;
        }
        if (!data.isRelay && sessions.has(peerId)) {
          sessions.get(peerId).pathMode = "direct";
          self.postMessage({ type: "path-upgraded", peerId, mode: "direct" });
        }
      }
      break;
    }

    case "raw-rx": {
      const peerId = formatNodeIdHex(toNodeIdBigInt(data.peerId));
      if (typeof data.bufferedAmount === "number" && links.has(peerId)) {
        links.get(peerId).bufferedAmount = data.bufferedAmount;
      }
      handleInboundRawPacket(data.buffer, peerId);
      break;
    }

    case "kcp-send": {
      const peerId = formatNodeIdHex(toNodeIdBigInt(data.peerId));
      const sess = getOrCreateSession(peerId);
      const bytes = new Uint8Array(data.payload);
      sess.kcp.send(bytes);
      sess.kcp.flush();
      break;
    }

    case "send-inband-signal": {
      const dstPeerId = formatNodeIdHex(toNodeIdBigInt(data.targetPeerId));
      const signalObj = { ...data.signal };
      if (signalObj.sdp) {
        signalObj.sdp = compactSignalingSDP(signalObj.sdp);
      }
      const rawJson = new TextEncoder().encode(JSON.stringify(signalObj));
      const pkt = encodeOverlayPacket(
        {
          srcNodeId: selfNodeId,
          dstNodeId: dstPeerId,
          type: PacketType.SIGNALING,
        },
        rawJson
      );
      const relayLink = defaultRelayPeerId ? links.get(defaultRelayPeerId) : links.values().next().value;
      if (relayLink) {
        transmitRawOnLink(relayLink, pkt);
      }
      break;
    }
  }
};

// 10ms high-frequency KCP tick inside Web Worker (unaffected by main-thread rendering)
setInterval(() => {
  const now = nowMs();
  for (const sess of sessions.values()) {
    sess.kcp.update(now);
  }
}, 10);
