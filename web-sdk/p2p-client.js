/**
 * @fileoverview Browser Peer SDK exposing an ultra-simple `const c = await peer.connect(id)` API.
 *
 * Key Architectural Features:
 *   1. WebRTC DataChannel strictly configured as `{ ordered: false, maxRetransmits: 0 }`
 *      (pure UDP-like virtual NIC).
 *   2. Offloads KCP ARQ, 20-byte Overlay Routing, E2EE, and 3-level SCTP Backpressure Valve
 *      into a dedicated Web Worker (`p2p-worker.js`), transferring `RTCDataChannel` ownership
 *      directly to the Worker thread when supported.
 *   3. 0-RTT Relay + Background In-Band SDP Hole Punching + Seamless Hot Path Upgrade:
 *      `const c = await peer.connect(targetId)` returns immediately and sends data via any
 *      connected SuperNode relay in 0ms while silently exchanging compressed SDP Offers/Answers
 *      in-band (`PacketType = 0x3 SIGNALING`) to upgrade to direct P2P without dropping a packet.
 */

import { toNodeIdBigInt, formatNodeIdHex } from "./kcp-engine.js";

/**
 * Virtual reliable KCP connection returned by `const c = await peer.connect(id)`.
 */
export class VirtualP2PConnection {
  constructor(peerClient, remotePeerId) {
    this._client = peerClient;
    this.remotePeerId = formatNodeIdHex(toNodeIdBigInt(remotePeerId));
    this.pathMode = "relay"; // Starts in 0-RTT relay mode, hot-upgrades to "direct"
    this.backpressurePaused = false;
    this._messageListeners = new Set();
    this._stateListeners = new Set();
  }

  /**
   * Sends a string or Uint8Array/ArrayBuffer reliably over the KCP + E2EE overlay channel.
   * @param {string|Uint8Array|ArrayBuffer} data
   */
  send(data) {
    let bytes;
    if (typeof data === "string") {
      bytes = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array) {
      bytes = data.slice();
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data.slice(0));
    } else {
      bytes = new TextEncoder().encode(JSON.stringify(data));
    }
    this._client._worker.postMessage(
      {
        type: "kcp-send",
        peerId: this.remotePeerId,
        payload: bytes.buffer,
      },
      [bytes.buffer]
    );
  }

  /**
   * Registers a callback for incoming reassembled KCP messages.
   * @param {(evt: {data: Uint8Array, text: () => string, relayed: boolean}) => void} fn
   */
   onMessage(fn) {
    this._messageListeners.add(fn);
    return () => this._messageListeners.delete(fn);
  }

  /**
   * Registers a listener for seamless path upgrades (`relay` -> `direct`) and backpressure changes.
   */
  onStateChange(fn) {
    this._stateListeners.add(fn);
    return () => this._stateListeners.delete(fn);
  }

  _emitMessage(buffer, relayed) {
    const bytes = new Uint8Array(buffer);
    const evt = {
      data: bytes,
      relayed,
      text: () => new TextDecoder().decode(bytes),
    };
    for (const fn of this._messageListeners) {
      fn(evt);
    }
  }

  _emitState(update) {
    Object.assign(this, update);
    for (const fn of this._stateListeners) {
      fn(this);
    }
  }
}

export class BrowserOverlayPeer {
  /**
   * @param {object} options
   * @param {string} [options.lighthouseUrl] WebSocket URL of Lighthouse bootstrap server
   * @param {string} [options.workerUrl="./p2p-worker.js"]
   * @param {RTCIceServer[]} [options.iceServers]
   * @param {(conn: VirtualP2PConnection) => void} [options.onConnection]
   */
  constructor(options = {}) {
    this.lighthouseUrl = options.lighthouseUrl || null;
    this.workerUrl = options.workerUrl || "./p2p-worker.js";
    this.iceServers = options.iceServers || [{ urls: "stun:stun.l.google.com:19302" }];
    this.onConnection = options.onConnection || null;

    this.nodeId = options.nodeId
      ? formatNodeIdHex(toNodeIdBigInt(options.nodeId))
      : generateRandomNodeIdHex();

    /** @type {Map<string, VirtualP2PConnection>} */
    this.connections = new Map();
    /** @type {Map<string, RTCPeerConnection>} */
    this.peerConnections = new Map();
    /** @type {Map<string, RTCDataChannel>} */
    this.fallbackChannels = new Map();

    this._ws = null;
    this._worker = new Worker(this.workerUrl, { type: "module" });
    this._readyPromise = new Promise((resolve) => {
      this._resolveReady = resolve;
    });

    this._worker.onmessage = (ev) => this._handleWorkerMessage(ev.data);
    this._worker.postMessage({ type: "init", nodeId: this.nodeId });

    if (this.lighthouseUrl) {
      this._connectLighthouse();
    }
  }

  async ready() {
    return this._readyPromise;
  }

  /**
   * Connects to a remote peer by its 64-bit NodeID (`const c = await peer.connect(id)`).
   *
   * Returns immediately (0-RTT): packets are sent via any active SuperNode relay first
   * while a direct `{ordered: false, maxRetransmits: 0}` WebRTC DataChannel is punched
   * in the background and hot-swapped without interrupting KCP.
   *
   * @param {string|bigint} remotePeerId
   * @returns {Promise<VirtualP2PConnection>}
   */
  async connect(remotePeerId) {
    await this.ready();
    const normId = formatNodeIdHex(toNodeIdBigInt(remotePeerId));
    if (this.connections.has(normId)) {
      return this.connections.get(normId);
    }
    const conn = new VirtualP2PConnection(this, normId);
    this.connections.set(normId, conn);
    return conn;
  }

  /**
   * Attaches an already-created `{ordered: false, maxRetransmits: 0}` RTCDataChannel
   * (e.g. to a SuperNode relay or a local Loopback test peer) and hands it to the Web Worker.
   */
  attachDataChannel(remotePeerId, dc, isRelay = false) {
    const normId = formatNodeIdHex(toNodeIdBigInt(remotePeerId));
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = 16 * 1024;

    const handoff = () => {
      // Attempt zero-copy Transferable RTCDataChannel transfer to Web Worker first
      try {
        this._worker.postMessage(
          {
            type: "attach-datachannel",
            peerId: normId,
            channel: dc,
            isRelay,
          },
          [dc]
        );
        return;
      } catch (_) {
        // Fallback for browsers where RTCDataChannel is not yet in the Transferable list:
        // forward binary ArrayBuffers via zero-copy transferable ownership.
        this.fallbackChannels.set(normId, dc);
        this._worker.postMessage({
          type: "attach-datachannel",
          peerId: normId,
          isRelay,
        });
        dc.onmessage = (ev) => {
          const buf = ev.data;
          this._worker.postMessage(
            {
              type: "raw-rx",
              peerId: normId,
              buffer: buf,
              bufferedAmount: dc.bufferedAmount,
            },
            [buf]
          );
        };
      }
    };

    if (dc.readyState === "open") {
      handoff();
    } else {
      dc.addEventListener("open", handoff, { once: true });
    }
  }

  _handleWorkerMessage(msg) {
    switch (msg.type) {
      case "ready":
        this._resolveReady(this.nodeId);
        break;

      case "kcp-recv": {
        let conn = this.connections.get(msg.peerId);
        if (!conn) {
          conn = new VirtualP2PConnection(this, msg.peerId);
          this.connections.set(msg.peerId, conn);
          if (this.onConnection) {
            this.onConnection(conn);
          }
        }
        conn._emitMessage(msg.payload, msg.relayed);
        break;
      }

      case "path-upgraded": {
        const conn = this.connections.get(msg.peerId);
        if (conn) {
          conn._emitState({ pathMode: msg.mode });
        }
        break;
      }

      case "backpressure": {
        const conn = this.connections.get(msg.peerId);
        if (conn) {
          conn._emitState({ backpressurePaused: msg.paused, backpressureMode: msg.mode });
        }
        break;
      }

      case "raw-tx": {
        const dc = this.fallbackChannels.get(msg.peerId);
        if (dc && dc.readyState === "open") {
          dc.send(msg.buffer);
        }
        break;
      }

      case "request-hole-punch": {
        this._startBackgroundHolePunch(msg.targetPeerId, false);
        break;
      }

      case "inband-signaling": {
        this._handleIncomingSignaling(msg.fromPeerId, msg.signal, true);
        break;
      }
    }
  }

  async _startBackgroundHolePunch(targetPeerId, viaLighthouse = false) {
    if (this.peerConnections.has(targetPeerId)) return;

    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    this.peerConnections.set(targetPeerId, pc);

    // Core requirement: strictly unordered, 0 retransmits (UDP-like virtual NIC)
    const dc = pc.createDataChannel("overlay-kcp-udp", {
      ordered: false,
      maxRetransmits: 0,
    });
    this.attachDataChannel(targetPeerId, dc, viaLighthouse);

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this._sendSignal(
          targetPeerId,
          { action: "candidate", candidate: ev.candidate },
          viaLighthouse
        );
      }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this._sendSignal(
      targetPeerId,
      { action: "offer", sdp: offer.sdp },
      viaLighthouse
    );
  }

  async _handleIncomingSignaling(fromPeerId, signal, inband) {
    let pc = this.peerConnections.get(fromPeerId);
    if (!pc) {
      pc = new RTCPeerConnection({ iceServers: this.iceServers });
      this.peerConnections.set(fromPeerId, pc);
      pc.ondatachannel = (ev) => {
        this.attachDataChannel(fromPeerId, ev.channel, false);
      };
      pc.onicecandidate = (ev) => {
        if (ev.candidate) {
          this._sendSignal(fromPeerId, { action: "candidate", candidate: ev.candidate }, !inband);
        }
      };
    }

    if (signal.action === "offer") {
      await pc.setRemoteDescription({ type: "offer", sdp: signal.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      this._sendSignal(fromPeerId, { action: "answer", sdp: answer.sdp }, !inband);
    } else if (signal.action === "answer") {
      await pc.setRemoteDescription({ type: "answer", sdp: signal.sdp });
    } else if (signal.action === "candidate" && signal.candidate) {
      await pc.addIceCandidate(signal.candidate);
    }
  }

  _sendSignal(targetPeerId, signal, viaLighthouse) {
    if (viaLighthouse && this._ws && this._ws.readyState === WebSocket.OPEN) {
      this._ws.send(
        JSON.stringify({
          type: "signal",
          target_id: targetPeerId,
          signal,
        })
      );
    } else {
      // Send in-band inside the 20-byte Overlay Packet (PacketType = 0x3 SIGNALING)
      this._worker.postMessage({
        type: "send-inband-signal",
        targetPeerId,
        signal,
      });
    }
  }

  _connectLighthouse() {
    const ws = new WebSocket(this.lighthouseUrl);
    this._ws = ws;
    ws.onopen = () => {
      ws.send(
        JSON.stringify({
          type: "register",
          node_id: this.nodeId,
          role: "browser",
        })
      );
    };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "welcome" && Array.isArray(msg.seeds) && msg.seeds.length > 0) {
          // Cold-start: connect to the first SuperNode seed
          const superSeed = msg.seeds[0];
          this._startBackgroundHolePunch(superSeed.node_id, true);
        } else if (msg.type === "signal" && msg.from_id && msg.signal) {
          this._handleIncomingSignaling(msg.from_id, msg.signal, false);
        }
      } catch (_) {}
    };
  }
}

function generateRandomNodeIdHex() {
  const bytes = new Uint8Array(8);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 8; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
