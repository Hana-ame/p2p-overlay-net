/**
 * Automated verification script for the Browser Sans-IO 20-byte Overlay Header,
 * 1200-byte MTU ceiling, 3-Level SCTP Backpressure Valve, E2EE authentication,
 * and KCP ARQ loss recovery.
 */
import assert from "node:assert/strict";
import {
  MAX_PHYSICAL_MTU,
  PacketType,
  HeaderFlags,
  BackpressureMode,
  encodeOverlayPacket,
  decodeOverlayPacket,
  compactSignalingSDP,
  ZeroRTTE2EE,
  KCPConnection,
} from "./kcp-engine.js";

console.log("[1/4] Verifying 20-byte Overlay Routing Header & 1200-byte MTU enforcement...");
const nodeA = "aaaa000000000001";
const nodeB = "bbbb000000000002";
const samplePayload = new TextEncoder().encode("overlay-test-payload");

const encoded = encodeOverlayPacket(
  {
    srcNodeId: nodeA,
    dstNodeId: nodeB,
    type: PacketType.KCP_DATA,
    flags: HeaderFlags.ENCRYPTED,
  },
  samplePayload
);
assert.equal(encoded.byteLength, 20 + samplePayload.byteLength);

const decoded = decodeOverlayPacket(encoded);
assert.equal(decoded.srcNodeId, nodeA);
assert.equal(decoded.dstNodeId, nodeB);
assert.equal(decoded.type, PacketType.KCP_DATA);
assert.equal(new TextDecoder().decode(decoded.payload), "overlay-test-payload");

console.log("[2/4] Verifying 3-Level SCTP Backpressure Valve...");
const bpEvents = [];
const bpKcp = new KCPConnection(
  42,
  () => {},
  (paused, mode) => bpEvents.push({ paused, mode })
);
assert.equal(bpKcp.updateBackpressure(0), BackpressureMode.TURBO);
assert.equal(bpKcp.updateBackpressure(32 * 1024), BackpressureMode.MILD);
assert.equal(bpKcp.updateBackpressure(128 * 1024), BackpressureMode.CIRCUIT);
assert.throws(() => bpKcp.send("blocked-while-circuit-open"), /SCTP_BACKPRESSURE_CIRCUIT_OPEN/);
assert.equal(bpKcp.updateBackpressure(0), BackpressureMode.TURBO);

console.log("[3/4] Verifying KCP Multi-Segment Fragmentation, 10% Loss Recovery & E2EE...");
const e2eeA = new ZeroRTTE2EE(nodeA, nodeB);
const e2eeB = new ZeroRTTE2EE(nodeB, nodeA);

const wireAtoB = [];
const wireBtoA = [];

const kcpA = new KCPConnection(9001, (kcpFrame) => {
  const cipher = e2eeA.seal(kcpFrame);
  const pkt = encodeOverlayPacket(
    { srcNodeId: nodeA, dstNodeId: nodeB, type: PacketType.KCP_DATA, flags: HeaderFlags.ENCRYPTED },
    cipher
  );
  assert.ok(pkt.byteLength <= MAX_PHYSICAL_MTU, `MTU exceeded: ${pkt.byteLength}`);
  wireAtoB.push(pkt);
});

const kcpB = new KCPConnection(9001, (kcpFrame) => {
  const cipher = e2eeB.seal(kcpFrame);
  const pkt = encodeOverlayPacket(
    { srcNodeId: nodeB, dstNodeId: nodeA, type: PacketType.KCP_DATA, flags: HeaderFlags.ENCRYPTED },
    cipher
  );
  assert.ok(pkt.byteLength <= MAX_PHYSICAL_MTU, `MTU exceeded: ${pkt.byteLength}`);
  wireBtoA.push(pkt);
});

const bigMsg = "P2P-OVERLAY-KCP-VERIFICATION-".repeat(160); // ~4640 bytes (5 segments of <=1140B)
kcpA.send(bigMsg);

let clock = 100;
let droppedFirst = false;
let receivedMsg = null;

for (let tick = 0; tick < 40; tick++) {
  clock += 15;
  kcpA.update(clock);
  kcpB.update(clock);

  while (wireAtoB.length > 0) {
    const raw = wireAtoB.shift();
    if (!droppedFirst) {
      droppedFirst = true; // Drop 1st segment to verify KCP fast retransmit / ARQ
      continue;
    }
    const hdr = decodeOverlayPacket(raw);
    const plain = e2eeB.open(hdr.payload);
    kcpB.input(plain, clock);
  }

  while (wireBtoA.length > 0) {
    const raw = wireBtoA.shift();
    const hdr = decodeOverlayPacket(raw);
    const plain = e2eeA.open(hdr.payload);
    kcpA.input(plain, clock);
  }

  const out = kcpB.recv();
  if (out) {
    receivedMsg = new TextDecoder().decode(out);
    break;
  }
}

assert.equal(receivedMsg, bigMsg, "Reassembled KCP payload did not match original");

console.log("[4/4] Verifying In-Band Signaling SDP Compaction...");
const verboseSdp = [
  "v=0",
  "o=- 12345 2 IN IP4 127.0.0.1",
  "a=rtpmap:96 VP8/90000",
  "a=fmtp:96 max-fr=30",
  "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
  "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
  "a=sctp-port:5000",
].join("\r\n");
const compacted = compactSignalingSDP(verboseSdp);
assert.ok(!compacted.includes("rtpmap") && compacted.includes("webrtc-datachannel"));

console.log("ALL BROWSER OVERLAY + KCP + E2EE TESTS PASSED!");
