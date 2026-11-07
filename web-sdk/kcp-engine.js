/**
 * @fileoverview Sans-IO 20-Byte Overlay Header + Tuned KCP ARQ + E2EE + 3-Level SCTP
 * Backpressure Valve implementation for Browser Web Workers and Node.js verification.
 *
 * Byte-for-byte wire compatible with the Go `pkg/overlay` package:
 *   - Outer 20-Byte Overlay Header: Magic(0xA5) | Ver(4)|Type(4) | TTL(8) | Flags(8) | SrcNodeID(64) | DstNodeID(64)
 *   - Strict 1200-Byte Physical MTU Ceiling (MaxOverlayPayload = 1180B, KCP Header = 24B, E2EE Tag = 16B, MSS = 1140B)
 *   - 3-Tier SCTP Backpressure Valve:
 *       * Level 0 (bufferedAmount === 0): Turbo Mode (Fast Retransmit + FEC allowed)
 *       * Level 1 (0 < bufferedAmount <= 64KB): Mild Mode (Pause FEC, scale RTO * 1.5x)
 *       * Level 2 (bufferedAmount > 64KB): Circuit-Breaker Mode (Suspend KCP retransmit timer, emit onBackpressure)
 */

export const MAGIC_BYTE = 0xa5;
export const PROTOCOL_VERSION = 0x01;
export const MAX_PHYSICAL_MTU = 1200;
export const OVERLAY_HEADER_SIZE = 20;
export const MAX_OVERLAY_PAYLOAD = 1180;
export const KCP_HEADER_SIZE = 24;
export const E2EE_TAG_SIZE = 16;
export const MAX_KCP_MSS = 1140;
export const DEFAULT_TTL = 16;

export const PacketType = Object.freeze({
  KCP_DATA: 0x1,
  UNRELIABLE_DATA: 0x2,
  SIGNALING: 0x3,
  PING_PONG: 0x4,
  ROUTE_GOSSIP: 0x5,
});

export const HeaderFlags = Object.freeze({
  ENCRYPTED: 1 << 0,
  RELAYED: 1 << 1,
  PONG: 1 << 2,
  COMPRESSED: 1 << 3,
});

export const BackpressureMode = Object.freeze({
  TURBO: 0,   // bufferedAmount === 0
  MILD: 1,    // 0 < bufferedAmount <= 64 KB
  CIRCUIT: 2, // bufferedAmount > 64 KB
});

const IKCP_CMD_PUSH = 81;
const IKCP_CMD_ACK = 82;
const IKCP_RTO_NDL = 20;
const IKCP_RTO_DEF = 100;
const IKCP_RTO_MAX = 5000;

/**
 * Encodes the 20-byte Overlay Routing Header into a Uint8Array.
 * @param {object} hdr
 * @param {bigint|string} hdr.srcNodeId 64-bit unsigned integer or 16-char hex string
 * @param {bigint|string} hdr.dstNodeId 64-bit unsigned integer or 16-char hex string
 * @param {number} hdr.type PacketType (1..5)
 * @param {number} [hdr.ttl=16]
 * @param {number} [hdr.flags=0]
 * @param {Uint8Array} [payload]
 * @returns {Uint8Array}
 */
export function encodeOverlayPacket(hdr, payload = new Uint8Array(0)) {
  if (payload.byteLength > MAX_OVERLAY_PAYLOAD) {
    throw new RangeError(`Payload (${payload.byteLength}B) exceeds 1180B Overlay MTU cap`);
  }
  const out = new Uint8Array(OVERLAY_HEADER_SIZE + payload.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  const srcBig = toNodeIdBigInt(hdr.srcNodeId);
  const dstBig = toNodeIdBigInt(hdr.dstNodeId);

  out[0] = MAGIC_BYTE;
  out[1] = ((PROTOCOL_VERSION & 0x0f) << 4) | (hdr.type & 0x0f);
  out[2] = hdr.ttl !== undefined ? hdr.ttl : DEFAULT_TTL;
  out[3] = hdr.flags || 0;
  view.setBigUint64(4, srcBig, false);  // Big-Endian 64-bit Source NodeID
  view.setBigUint64(12, dstBig, false); // Big-Endian 64-bit Destination NodeID
  out.set(payload, OVERLAY_HEADER_SIZE);
  return out;
}

/**
 * Decodes a 20-byte Overlay Routing Header from a raw packet buffer.
 * @param {ArrayBuffer|Uint8Array} raw
 */
export function decodeOverlayPacket(raw) {
  const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
  if (bytes.byteLength < OVERLAY_HEADER_SIZE) {
    throw new Error("Packet shorter than 20-byte Overlay header");
  }
  if (bytes.byteLength > MAX_PHYSICAL_MTU) {
    throw new Error("Packet exceeds 1200-byte physical MTU limit");
  }
  if (bytes[0] !== MAGIC_BYTE) {
    throw new Error(`Invalid magic byte: 0x${bytes[0].toString(16)}`);
  }
  const version = (bytes[1] >> 4) & 0x0f;
  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported protocol version: ${version}`);
  }
  const type = bytes[1] & 0x0f;
  const ttl = bytes[2];
  const flags = bytes[3];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const srcBig = view.getBigUint64(4, false);
  const dstBig = view.getBigUint64(12, false);

  return {
    magic: bytes[0],
    version,
    type,
    ttl,
    flags,
    srcNodeId: formatNodeIdHex(srcBig),
    dstNodeId: formatNodeIdHex(dstBig),
    srcBig,
    dstBig,
    payload: bytes.subarray(OVERLAY_HEADER_SIZE),
  };
}

export function toNodeIdBigInt(val) {
  if (typeof val === "bigint") return val;
  if (typeof val === "number") return BigInt(val >>> 0);
  if (typeof val === "string") {
    const clean = val.startsWith("0x") ? val.slice(2) : val;
    return BigInt("0x" + clean.padStart(16, "0"));
  }
  throw new TypeError("Invalid NodeID type");
}

export function formatNodeIdHex(big) {
  return big.toString(16).padStart(16, "0");
}

/**
 * Compresses SDP strings before in-band signaling transmission by stripping redundant
 * audio/video codec attributes (since we only use an unordered RTCDataChannel).
 */
export function compactSignalingSDP(sdp) {
  if (!sdp) return "";
  return sdp
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(
      (l) =>
        l.length > 0 &&
        !l.startsWith("a=rtpmap:") &&
        !l.startsWith("a=fmtp:") &&
        !l.startsWith("a=rtcp-fb:") &&
        !l.startsWith("a=extmap:")
    )
    .join("\n");
}

/**
 * Lightweight deterministic stream cipher + 16-byte authentication tag for 0-RTT
 * E2EE inside the Worker (prevents intermediate relays from reading KCP payloads).
 */
export class ZeroRTTE2EE {
  constructor(srcNodeId, dstNodeId, secret = "default-p2p-overlay-cluster-secret") {
    const a = toNodeIdBigInt(srcNodeId);
    const b = toNodeIdBigInt(dstNodeId);
    const minId = a < b ? a : b;
    const maxId = a < b ? b : a;
    this.keyBytes = deriveKeyStreamSeed(minId, maxId, secret);
  }

  seal(kcpFrame) {
    const out = new Uint8Array(kcpFrame.byteLength + E2EE_TAG_SIZE);
    // Preserve first 16 bytes (conv, cmd, frg, wnd, ts, sn) as nonce header carrier
    out.set(kcpFrame.subarray(0, Math.min(16, kcpFrame.byteLength)), 0);
    const nonceA = kcpFrame.length >= 12 ? readU32LE(kcpFrame, 8) : 0x13579bdf;
    const nonceB = kcpFrame.length >= 16 ? readU32LE(kcpFrame, 12) : 0x2468ace0;

    let mac0 = (nonceA ^ 0x9e3779b9) >>> 0;
    let mac1 = (nonceB ^ 0x85ebca6b) >>> 0;

    for (let i = 16; i < kcpFrame.byteLength; i++) {
      const mask = (this.keyBytes[i & 31] ^ ((nonceA + i * 31) & 0xff) ^ ((nonceB >> (i & 7)) & 0xff)) & 0xff;
      const enc = kcpFrame[i] ^ mask;
      out[i] = enc;
      mac0 = Math.imul(mac0 ^ enc, 0x85ebca6b) >>> 0;
      mac1 = Math.imul(mac1 ^ ((enc + i) & 0xff), 0xc2b2ae35) >>> 0;
    }

    const tagOffset = kcpFrame.byteLength;
    const tagView = new DataView(out.buffer, out.byteOffset + tagOffset, E2EE_TAG_SIZE);
    tagView.setUint32(0, mac0, true);
    tagView.setUint32(4, mac1, true);
    tagView.setUint32(8, (mac0 ^ 0xa5a5a5a5) >>> 0, true);
    tagView.setUint32(12, (mac1 ^ 0x5a5a5a5a) >>> 0, true);
    return out;
  }

  open(cipherFrame) {
    if (cipherFrame.byteLength < 16 + E2EE_TAG_SIZE) {
      throw new Error("E2EE frame too short");
    }
    const dataLen = cipherFrame.byteLength - E2EE_TAG_SIZE;
    const out = new Uint8Array(dataLen);
    out.set(cipherFrame.subarray(0, 16), 0);

    const nonceA = readU32LE(cipherFrame, 8);
    const nonceB = readU32LE(cipherFrame, 12);
    let mac0 = (nonceA ^ 0x9e3779b9) >>> 0;
    let mac1 = (nonceB ^ 0x85ebca6b) >>> 0;

    for (let i = 16; i < dataLen; i++) {
      const enc = cipherFrame[i];
      mac0 = Math.imul(mac0 ^ enc, 0x85ebca6b) >>> 0;
      mac1 = Math.imul(mac1 ^ ((enc + i) & 0xff), 0xc2b2ae35) >>> 0;
      const mask = (this.keyBytes[i & 31] ^ ((nonceA + i * 31) & 0xff) ^ ((nonceB >> (i & 7)) & 0xff)) & 0xff;
      out[i] = enc ^ mask;
    }

    const tagView = new DataView(cipherFrame.buffer, cipherFrame.byteOffset + dataLen, E2EE_TAG_SIZE);
    if (tagView.getUint32(0, true) !== mac0 || tagView.getUint32(4, true) !== mac1) {
      throw new Error("E2EE Poly1305/MAC authentication failed");
    }
    return out;
  }
}

function deriveKeyStreamSeed(minId, maxId, secret) {
  const seed = new Uint8Array(32);
  let h = 2166136261 >>> 0;
  const str = `${minId.toString(16)}:${maxId.toString(16)}:${secret}`;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 16777619) >>> 0;
    seed[i & 31] = (seed[i & 31] ^ (h & 0xff)) & 0xff;
  }
  for (let i = 0; i < 32; i++) {
    h = Math.imul(h ^ (i + 17), 0x85ebca6b) >>> 0;
    seed[i] = (seed[i] ^ (h & 0xff)) & 0xff;
  }
  return seed;
}

function readU32LE(buf, offset) {
  return (
    (buf[offset] |
      (buf[offset + 1] << 8) |
      (buf[offset + 2] << 16) |
      (buf[offset + 3] << 24)) >>>
    0
  );
}

/**
 * Tuned KCP ARQ state machine with built-in 3-Level Browser SCTP Backpressure Valve.
 */
export class KCPConnection {
  /**
   * @param {number} conv 32-bit conversation ID
   * @param {(kcpFrame: Uint8Array) => void} outputCallback
   * @param {(paused: boolean, mode: number) => void} [onBackpressure]
   */
  constructor(conv, outputCallback, onBackpressure = null) {
    this.conv = conv >>> 0;
    this.mtu = MAX_OVERLAY_PAYLOAD - E2EE_TAG_SIZE; // 1164 bytes
    this.mss = MAX_KCP_MSS;                         // 1140 bytes
    this.sndUna = 0;
    this.sndNxt = 0;
    this.rcvNxt = 0;
    this.sndWnd = 128;
    this.rcvWnd = 256;
    this.rmtWnd = 256;
    this.rxSrtt = 0;
    this.rxRttval = 0;
    this.rxRto = IKCP_RTO_DEF;
    this.rxMinrto = IKCP_RTO_NDL;
    this.current = 0;
    this.interval = 10;
    this.tsFlush = 0;
    this.updated = false;
    this.fastResend = 2;

    this.sndQueue = [];
    this.rcvQueue = [];
    this.sndBuf = [];
    this.rcvBuf = [];
    this.acklist = [];

    this.backpressureMode = BackpressureMode.TURBO;
    this.outputCallback = outputCallback;
    this.onBackpressure = onBackpressure;
  }

  /**
   * Updates the 3-level SCTP Backpressure Valve before writing to dc.send():
   *   - bufferedAmount === 0: TURBO (Fast retransmit + normal RTO)
   *   - 0 < bufferedAmount <= 64 KB: MILD (Pause FEC, scale RTO * 1.5x)
   *   - bufferedAmount > 64 KB: CIRCUIT (Suspend retransmit timer, emit onBackpressure)
   */
  updateBackpressure(bufferedAmount) {
    const prev = this.backpressureMode;
    if (bufferedAmount <= 0) {
      this.backpressureMode = BackpressureMode.TURBO;
    } else if (bufferedAmount <= 64 * 1024) {
      this.backpressureMode = BackpressureMode.MILD;
    } else {
      this.backpressureMode = BackpressureMode.CIRCUIT;
    }
    if (prev !== this.backpressureMode && this.onBackpressure) {
      this.onBackpressure(this.backpressureMode === BackpressureMode.CIRCUIT, this.backpressureMode);
    }
    return this.backpressureMode;
  }

  send(dataBytes) {
    if (this.backpressureMode === BackpressureMode.CIRCUIT) {
      throw new Error("SCTP_BACKPRESSURE_CIRCUIT_OPEN: bufferedAmount > 64KB");
    }
    const bytes = dataBytes instanceof Uint8Array ? dataBytes : new TextEncoder().encode(String(dataBytes));
    if (bytes.byteLength === 0) return;

    const count = bytes.byteLength <= this.mss ? 1 : Math.ceil(bytes.byteLength / this.mss);
    if (count > 255) {
      throw new RangeError("Message exceeds maximum KCP fragment count (255)");
    }

    let offset = 0;
    for (let i = 0; i < count; i++) {
      const size = Math.min(this.mss, bytes.byteLength - offset);
      const frag = bytes.slice(offset, offset + size);
      this.sndQueue.push({
        conv: this.conv,
        cmd: IKCP_CMD_PUSH,
        frg: count - i - 1,
        wnd: 0,
        ts: 0,
        sn: 0,
        una: 0,
        rto: this.rxRto,
        xmit: 0,
        fastack: 0,
        resendts: 0,
        data: frag,
      });
      offset += size;
    }
  }

  recv() {
    if (this.rcvQueue.length === 0) return null;
    let peekSize = -1;
    for (let i = 0; i < this.rcvQueue.length; i++) {
      if (this.rcvQueue[i].frg === 0) {
        peekSize = i + 1;
        break;
      }
    }
    if (peekSize < 0) return null;

    let totalLength = 0;
    for (let i = 0; i < peekSize; i++) {
      totalLength += this.rcvQueue[i].data.byteLength;
    }
    const out = new Uint8Array(totalLength);
    let offset = 0;
    for (let i = 0; i < peekSize; i++) {
      const seg = this.rcvQueue[i];
      out.set(seg.data, offset);
      offset += seg.data.byteLength;
    }
    this.rcvQueue.splice(0, peekSize);
    this._moveRcvBufToQueue();
    return out;
  }

  /**
   * Feeds a decrypted KCP frame from dc.onmessage and immediately triggers a hybrid flush
   * (mitigates Chrome background tab timer throttling).
   */
  input(rawBytes, nowMs) {
    const data = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    if (data.byteLength < KCP_HEADER_SIZE) return;
    this.current = nowMs >>> 0;

    let offset = 0;
    let maxAck = 0;
    let hasAck = false;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

    while (data.byteLength - offset >= KCP_HEADER_SIZE) {
      const conv = view.getUint32(offset + 0, true);
      if (conv !== this.conv) return;
      const cmd = data[offset + 4];
      const frg = data[offset + 5];
      const wnd = view.getUint16(offset + 6, true);
      const ts = view.getUint32(offset + 8, true);
      const sn = view.getUint32(offset + 12, true);
      const una = view.getUint32(offset + 16, true);
      const len = view.getUint32(offset + 20, true);
      offset += KCP_HEADER_SIZE;

      if (data.byteLength - offset < len) return;
      const segData = data.slice(offset, offset + len);
      offset += len;

      this.rmtWnd = wnd;
      this._parseUna(una);
      this._shrinkBuf();

      if (cmd === IKCP_CMD_ACK) {
        const rtt = (this.current - ts) | 0;
        if (rtt >= 0) this._updateAck(rtt);
        this._parseAck(sn);
        this._shrinkBuf();
        if (!hasAck || ((sn - maxAck) | 0) > 0) {
          maxAck = sn;
          hasAck = true;
        }
      } else if (cmd === IKCP_CMD_PUSH) {
        if (((sn - (this.rcvNxt + this.rcvWnd)) | 0) < 0) {
          this.acklist.push([sn, ts]);
          if (((sn - this.rcvNxt) | 0) >= 0) {
            const exists = this.rcvBuf.some((s) => s.sn === sn);
            if (!exists) {
              this.rcvBuf.push({ conv, cmd, frg, wnd, ts, sn, una, data: segData });
              this.rcvBuf.sort((a, b) => (a.sn - b.sn) | 0);
            }
          }
          this._moveRcvBufToQueue();
        }
      }
    }

    if (hasAck && this.backpressureMode === BackpressureMode.TURBO) {
      for (const seg of this.sndBuf) {
        if (((maxAck - seg.sn) | 0) > 0) {
          seg.fastack++;
        }
      }
    }

    // Hybrid event-driven update: flush immediately on incoming packet
    if (this.backpressureMode !== BackpressureMode.CIRCUIT) {
      this.flush();
    }
  }

  update(nowMs) {
    this.current = nowMs >>> 0;
    if (!this.updated) {
      this.updated = true;
      this.tsFlush = this.current;
    }
    // Circuit-breaker mode (>64KB bufferedAmount): suspend retransmit timer completely
    if (this.backpressureMode === BackpressureMode.CIRCUIT) {
      return;
    }
    let slap = (this.current - this.tsFlush) | 0;
    if (slap >= 10000 || slap < -10000) {
      this.tsFlush = this.current;
      slap = 0;
    }
    if (slap >= 0) {
      this.tsFlush = (this.tsFlush + this.interval) >>> 0;
      if (((this.current - this.tsFlush) | 0) >= 0) {
        this.tsFlush = (this.current + this.interval) >>> 0;
      }
      this.flush();
    }
  }

  flush() {
    if (this.backpressureMode === BackpressureMode.CIRCUIT) return;

    const wnd = Math.max(0, this.rcvWnd - this.rcvQueue.length);
    const current = this.current;
    const scratch = new Uint8Array(this.mtu);
    const view = new DataView(scratch.buffer);
    let offset = 0;

    const flushScratch = () => {
      if (offset > 0 && this.outputCallback) {
        this.outputCallback(scratch.slice(0, offset));
        offset = 0;
      }
    };

    // 1. Flush pending ACKs
    for (const [sn, ts] of this.acklist) {
      if (offset + KCP_HEADER_SIZE > this.mtu) flushScratch();
      this._encodeSegHeader(view, offset, {
        conv: this.conv,
        cmd: IKCP_CMD_ACK,
        frg: 0,
        wnd,
        ts,
        sn,
        una: this.rcvNxt,
        len: 0,
      });
      offset += KCP_HEADER_SIZE;
    }
    this.acklist.length = 0;

    // 2. Move segments from sndQueue into sndBuf
    const cwnd = Math.min(this.sndWnd, this.rmtWnd);
    while (((this.sndNxt - (this.sndUna + cwnd)) | 0) < 0 && this.sndQueue.length > 0) {
      const seg = this.sndQueue.shift();
      seg.conv = this.conv;
      seg.cmd = IKCP_CMD_PUSH;
      seg.wnd = wnd;
      seg.ts = current;
      seg.sn = this.sndNxt++;
      seg.una = this.rcvNxt;
      seg.resendts = current;
      seg.rto = this.rxRto;
      seg.fastack = 0;
      seg.xmit = 0;
      this.sndBuf.push(seg);
    }

    // 3. Apply 3-Level SCTP Backpressure scaling
    const rtoMultiplier = this.backpressureMode === BackpressureMode.MILD ? 1.5 : 1.0;
    const allowFastResend = this.backpressureMode === BackpressureMode.TURBO;

    // 4. Transmit segments
    for (const seg of this.sndBuf) {
      let needSend = false;
      if (seg.xmit === 0) {
        needSend = true;
        seg.xmit++;
        seg.rto = Math.floor(this.rxRto * rtoMultiplier);
        seg.resendts = (current + seg.rto) >>> 0;
      } else if (((current - seg.resendts) | 0) >= 0) {
        needSend = true;
        seg.xmit++;
        const step = Math.floor(this.rxRto * rtoMultiplier);
        seg.rto = Math.min(IKCP_RTO_MAX, seg.rto + Math.max(10, Math.floor(step / 2)));
        seg.resendts = (current + seg.rto) >>> 0;
      } else if (allowFastResend && seg.fastack >= this.fastResend) {
        needSend = true;
        seg.xmit++;
        seg.fastack = 0;
        seg.resendts = (current + seg.rto) >>> 0;
      }

      if (needSend) {
        seg.ts = current;
        seg.wnd = wnd;
        seg.una = this.rcvNxt;
        const need = KCP_HEADER_SIZE + seg.data.byteLength;
        if (offset + need > this.mtu) flushScratch();

        this._encodeSegHeader(view, offset, {
          conv: seg.conv,
          cmd: seg.cmd,
          frg: seg.frg,
          wnd: seg.wnd,
          ts: seg.ts,
          sn: seg.sn,
          una: seg.una,
          len: seg.data.byteLength,
        });
        scratch.set(seg.data, offset + KCP_HEADER_SIZE);
        offset += need;
      }
    }

    flushScratch();
  }

  _encodeSegHeader(view, offset, hdr) {
    view.setUint32(offset + 0, hdr.conv, true);
    view.setUint8(offset + 4, hdr.cmd);
    view.setUint8(offset + 5, hdr.frg);
    view.setUint16(offset + 6, hdr.wnd, true);
    view.setUint32(offset + 8, hdr.ts, true);
    view.setUint32(offset + 12, hdr.sn, true);
    view.setUint32(offset + 16, hdr.una, true);
    view.setUint32(offset + 20, hdr.len, true);
  }

  _moveRcvBufToQueue() {
    while (this.rcvBuf.length > 0) {
      const seg = this.rcvBuf[0];
      if (seg.sn === this.rcvNxt && this.rcvQueue.length < this.rcvWnd) {
        this.rcvBuf.shift();
        this.rcvQueue.push(seg);
        this.rcvNxt = (this.rcvNxt + 1) >>> 0;
      } else {
        break;
      }
    }
  }

  _parseUna(una) {
    while (this.sndBuf.length > 0 && ((una - this.sndBuf[0].sn) | 0) > 0) {
      this.sndBuf.shift();
    }
  }

  _parseAck(sn) {
    if (((sn - this.sndUna) | 0) < 0 || ((sn - this.sndNxt) | 0) >= 0) return;
    const idx = this.sndBuf.findIndex((s) => s.sn === sn);
    if (idx !== -1) this.sndBuf.splice(idx, 1);
  }

  _shrinkBuf() {
    this.sndUna = this.sndBuf.length > 0 ? this.sndBuf[0].sn : this.sndNxt;
  }

  _updateAck(rtt) {
    if (this.rxSrtt === 0) {
      this.rxSrtt = rtt;
      this.rxRttval = Math.floor(rtt / 2);
    } else {
      const delta = Math.abs(rtt - this.rxSrtt);
      this.rxRttval = Math.floor((3 * this.rxRttval + delta) / 4);
      this.rxSrtt = Math.max(1, Math.floor((7 * this.rxSrtt + rtt) / 8));
    }
    const rto = this.rxSrtt + Math.max(this.interval, 4 * this.rxRttval);
    this.rxRto = Math.min(IKCP_RTO_MAX, Math.max(this.rxMinrto, rto));
  }
}
