package overlay

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// LinkType distinguishes between a relay path via a Native Peer and a direct P2P channel.
type LinkType uint8

const (
	LinkTypeRelay      LinkType = 1 // Via intermediate Native Peer (0-RTT immediate fallback)
	LinkTypeDirectRTC  LinkType = 2 // Direct WebRTC DataChannel (ordered:false, maxRetransmits:0)
	LinkTypeDirectUDP  LinkType = 3 // Direct Raw UDP socket (Native <-> Native)
)

// TransportLink abstracts an underlying unreliable datagram pipe (WebRTC DataChannel or Raw UDP).
type TransportLink interface {
	ID() string
	RemoteNodeID() NodeID
	Type() LinkType
	SendRaw(packet []byte) error
	BufferedAmount() int
	RTT() time.Duration
	Close() error
}

// RouteEntry tracks both the active direct link (if punched) and the best relay link
// to reach a destination NodeID.
type RouteEntry struct {
	DstNodeID      NodeID
	DirectLink     TransportLink
	RelayLink      TransportLink
	RelayViaNodeID NodeID
	DirectRTT      time.Duration
	RelayRTT       time.Duration
	PunchInFlight  bool
	LastUpdated    time.Time
}

// SignalingEnvelope is the JSON structure compressed inside PacketTypeSignaling payloads.
type SignalingEnvelope struct {
	Action    string   `json:"a"`           // "offer", "answer", "candidate", "udp_probe"
	SDP       string   `json:"sdp,omitempty"`
	Candidate string   `json:"cand,omitempty"`
	UDPAddr   string   `json:"udp,omitempty"`
	PubKeyHex string   `json:"pub,omitempty"`
	Signature string   `json:"sig,omitempty"`
}

// Router manages the autonomous overlay routing table, zero-copy relay forwarding,
// and seamless 0-RTT Relay -> Direct P2P hot path upgrading.
type Router struct {
	mu           sync.RWMutex
	selfID       NodeID
	isSuperNode  bool
	routes       map[NodeID]*RouteEntry
	defaultRelay TransportLink
	rateLimiter  *RelayRateLimiter
	onHolePunch  func(targetID NodeID) // Triggered asynchronously on first relayed send
}

// NewRouter creates an Overlay Router for selfID.
func NewRouter(selfID NodeID, isSuperNode bool, onHolePunch func(targetID NodeID)) *Router {
	return &Router{
		selfID:      selfID,
		isSuperNode: isSuperNode,
		routes:      make(map[NodeID]*RouteEntry),
		rateLimiter: NewRelayRateLimiter(DefaultRelayRateBytesPerSec, DefaultRelayBurstBytes),
		onHolePunch: onHolePunch,
	}
}

// SetDefaultRelay registers a connected SuperNode (Native Peer) as the 0-RTT relay gateway.
func (r *Router) SetDefaultRelay(link TransportLink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultRelay = link
}

// UpgradeToDirect atomically upgrades the route for dstID to use a newly established
// direct WebRTC DataChannel or Raw UDP link without interrupting upper-layer KCP state.
func (r *Router) UpgradeToDirect(dstID NodeID, directLink TransportLink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.routes[dstID]
	if !ok {
		entry = &RouteEntry{DstNodeID: dstID}
		r.routes[dstID] = entry
	}
	entry.DirectLink = directLink
	entry.PunchInFlight = false
	entry.LastUpdated = time.Now()
}

// RegisterRelayRoute records a relay path to dstID via relayLink.
func (r *Router) RegisterRelayRoute(dstID NodeID, relayLink TransportLink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.routes[dstID]
	if !ok {
		entry = &RouteEntry{DstNodeID: dstID}
		r.routes[dstID] = entry
	}
	entry.RelayLink = relayLink
	entry.RelayViaNodeID = relayLink.RemoteNodeID()
	entry.LastUpdated = time.Now()
}

// SelectLink chooses the optimal transport link for dstID:
//  1. If a DirectLink exists (and its RTT isn't degraded compared to Relay), send directly.
//  2. Otherwise, immediately send via RelayLink or defaultRelay (0ms wait) AND asynchronously
//     trigger background SDP hole punching (`onHolePunch`) on the first packet.
func (r *Router) SelectLink(dstID NodeID) (TransportLink, bool, error) {
	r.mu.Lock()
	entry, ok := r.routes[dstID]
	if !ok {
		entry = &RouteEntry{DstNodeID: dstID, LastUpdated: time.Now()}
		r.routes[dstID] = entry
	}

	// Prefer direct link unless direct RTT is severely degraded compared to relay
	if entry.DirectLink != nil {
		if entry.RelayLink != nil && entry.DirectRTT > 0 && entry.RelayRTT > 0 &&
			entry.DirectRTT > entry.RelayRTT*2 {
			link := entry.RelayLink
			r.mu.Unlock()
			return link, true, nil
		}
		link := entry.DirectLink
		r.mu.Unlock()
		return link, false, nil
	}

	relay := entry.RelayLink
	if relay == nil {
		relay = r.defaultRelay
	}
	shouldPunch := !entry.PunchInFlight && r.onHolePunch != nil && dstID != r.selfID
	if shouldPunch {
		entry.PunchInFlight = true
	}
	r.mu.Unlock()

	if shouldPunch {
		go r.onHolePunch(dstID)
	}
	if relay == nil {
		return nil, false, errors.New("router: no direct link or relay available")
	}
	return relay, true, nil
}

// ForwardOrDeliver inspects only the 20-byte Overlay Header.
//   - If DstNodeID == selfID, returns (true, nil) so the caller delivers the payload locally.
//   - If DstNodeID != selfID and isSuperNode == true, applies the per-SrcNodeID Token Bucket
//     rate limiter, decrements TTL in-place (zero copy), and forwards the raw packet to the next hop.
func (r *Router) ForwardOrDeliver(rawPacket []byte, now time.Time) (deliverLocal bool, err error) {
	if len(rawPacket) < OverlayHeaderSize {
		return false, ErrPacketTooShort
	}
	hdr, err := DecodeHeader(rawPacket)
	if err != nil {
		return false, err
	}
	if hdr.DstNodeID == r.selfID {
		return true, nil
	}
	// Leaf nodes (Browser Peers) never relay traffic for other peers
	if !r.isSuperNode {
		return false, errors.New("router: leaf peer refuses relay forwarding")
	}

	// Enforce 500 KB/s per-SrcNodeID Token Bucket rate limit
	if !r.rateLimiter.Allow(hdr.SrcNodeID, len(rawPacket), now) {
		return false, errors.New("router: relay rate limit exceeded for source node")
	}

	// Zero-copy in-place TTL decrement + FlagRelayed bit
	_, dstID, err := DecrementTTLInPlace(rawPacket)
	if err != nil {
		return false, err
	}

	r.mu.RLock()
	entry := r.routes[dstID]
	var nextHop TransportLink
	if entry != nil {
		if entry.DirectLink != nil {
			nextHop = entry.DirectLink
		} else if entry.RelayLink != nil {
			nextHop = entry.RelayLink
		}
	}
	if nextHop == nil {
		nextHop = r.defaultRelay
	}
	r.mu.RUnlock()

	if nextHop == nil {
		return false, errors.New("router: no next hop for relayed packet")
	}
	return false, nextHop.SendRaw(rawPacket)
}

// PackSignalingPacket encodes and Deflate-compresses a SignalingEnvelope into a ready-to-send
// <=1200-byte Overlay Packet (PacketTypeSignaling).
func PackSignalingPacket(srcID, dstID NodeID, env SignalingEnvelope) ([]byte, error) {
	rawJSON, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	compressed, err := CompressSignalingSDP(string(rawJSON))
	if err != nil {
		return nil, err
	}
	if len(compressed) > MaxOverlayPayload {
		return nil, ErrPacketTooLarge
	}
	pkt := make([]byte, OverlayHeaderSize+len(compressed))
	hdr := Header{
		Magic:     MagicByte,
		Version:   ProtocolVersion,
		Type:      PacketTypeSignaling,
		TTL:       DefaultTTL,
		Flags:     FlagCompressed,
		SrcNodeID: srcID,
		DstNodeID: dstID,
	}
	if err := hdr.Encode(pkt[:OverlayHeaderSize]); err != nil {
		return nil, err
	}
	copy(pkt[OverlayHeaderSize:], compressed)
	return pkt, nil
}

// UnpackSignalingPacket inflates and unmarshals a PacketTypeSignaling payload.
func UnpackSignalingPacket(payload []byte, flags uint8) (SignalingEnvelope, error) {
	var env SignalingEnvelope
	data := payload
	if (flags & FlagCompressed) != 0 {
		str, err := DecompressSignalingSDP(payload)
		if err != nil {
			return env, err
		}
		data = []byte(str)
	}
	err := json.Unmarshal(data, &env)
	return env, err
}
