// Package overlay implements the platform-agnostic Sans-IO 20-byte routing protocol,
// tuned KCP ARQ state machine (1200-byte MTU cap), E2EE ChaCha20-Poly1305 session
// encryption, SDP deflate compression, and token-bucket relay rate limiting.
package overlay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// MagicByte is the fixed 1-byte protocol magic number (0xA5).
	MagicByte uint8 = 0xA5
	// ProtocolVersion is the 4-bit overlay protocol version (0x1).
	ProtocolVersion uint8 = 0x01

	// MaxPhysicalMTU is the strict 1200-byte physical packet ceiling for dc.send() and udp.send().
	MaxPhysicalMTU = 1200
	// OverlayHeaderSize is the fixed 20-byte outer routing header size.
	OverlayHeaderSize = 20
	// MaxOverlayPayload is the maximum payload carried inside an Overlay packet (1180 bytes).
	MaxOverlayPayload = MaxPhysicalMTU - OverlayHeaderSize
	// KCPHeaderSize is the 24-byte KCP segment header size.
	KCPHeaderSize = 24
	// E2EETagSize is the 16-byte Poly1305 authentication tag size.
	E2EETagSize = 16
	// MaxKCPUserPayload is the maximum single-segment user payload (1140 bytes).
	MaxKCPUserPayload = MaxOverlayPayload - KCPHeaderSize - E2EETagSize

	// DefaultTTL is the default hop limit for overlay routing packets.
	DefaultTTL uint8 = 16
)

// PacketType defines the 4-bit payload type in Byte 1 of the Overlay Header.
type PacketType uint8

const (
	PacketTypeKCPData        PacketType = 0x1 // Reliable KCP ARQ + E2EE frame
	PacketTypeUnreliableData PacketType = 0x2 // Pure real-time datagram (skips KCP, straight to app)
	PacketTypeSignaling      PacketType = 0x3 // In-band compressed SDP Offer/Answer or ICE Candidate
	PacketTypePingPong       PacketType = 0x4 // End-to-end RTT probe and NAT keepalive
	PacketTypeRouteGossip    PacketType = 0x5 // Node discovery and route table gossip exchange
)

// Header Flags (Byte 3)
const (
	FlagEncrypted uint8 = 1 << 0 // Payload carries E2EE ChaCha20-Poly1305 ciphertext
	FlagRelayed   uint8 = 1 << 1 // Packet has been forwarded by a Native Peer relay
	FlagPong      uint8 = 1 << 2 // Marks a PacketTypePingPong packet as a PONG reply
	FlagCompressed uint8 = 1 << 3 // Payload is deflate-compressed (used for SIGNALING)
)

var (
	ErrPacketTooShort = errors.New("overlay: packet shorter than 20-byte header")
	ErrPacketTooLarge = errors.New("overlay: packet exceeds 1200-byte MTU ceiling")
	ErrInvalidMagic   = errors.New("overlay: invalid magic byte (expected 0xA5)")
	ErrInvalidVersion = errors.New("overlay: unsupported protocol version")
	ErrTTLExpired     = errors.New("overlay: packet TTL expired")
)

// NodeID is a 64-bit globally unique identifier derived from the first 8 bytes
// of SHA-256(Ed25519_PublicKey).
type NodeID uint64

func (id NodeID) String() string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return hex.EncodeToString(b[:])
}

// ParseNodeID parses a 16-character hex string into a 64-bit NodeID.
func ParseNodeID(hexStr string) (NodeID, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 8 {
		return 0, fmt.Errorf("overlay: invalid 64-bit NodeID hex %q", hexStr)
	}
	return NodeID(binary.BigEndian.Uint64(b)), nil
}

// CryptoIdentity holds a node's Ed25519 keypair and its derived 64-bit NodeID.
type CryptoIdentity struct {
	NodeID     NodeID
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateIdentity creates a new Ed25519 keypair and derives its 64-bit Crypto-ID.
func GenerateIdentity() (*CryptoIdentity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return IdentityFromPrivateKey(priv), nil
}

// IdentityFromPrivateKey reconstructs a CryptoIdentity from an existing Ed25519 private key.
func IdentityFromPrivateKey(priv ed25519.PrivateKey) *CryptoIdentity {
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	id := NodeID(binary.BigEndian.Uint64(sum[:8]))
	return &CryptoIdentity{
		NodeID:     id,
		PublicKey:  pub,
		PrivateKey: priv,
	}
}

// DeriveNodeID computes the 64-bit NodeID from an Ed25519 public key.
func DeriveNodeID(pub ed25519.PublicKey) NodeID {
	sum := sha256.Sum256(pub)
	return NodeID(binary.BigEndian.Uint64(sum[:8]))
}

// VerifyNodeSignature checks that pub matches claimedID and that sig is valid over msg.
func VerifyNodeSignature(claimedID NodeID, pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || DeriveNodeID(pub) != claimedID {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// Header represents the fixed 20-byte outer Overlay Routing Header:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Magic (0xA5) | Ver(4)|Type(4)|      TTL      |     Flags     |  (4 Bytes)
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Source NodeID                         |
//	|                           (64-bit)                            |  (8 Bytes)
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                       Destination NodeID                      |
//	|                           (64-bit)                            |  (8 Bytes)
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Header struct {
	Magic     uint8
	Version   uint8
	Type      PacketType
	TTL       uint8
	Flags     uint8
	SrcNodeID NodeID
	DstNodeID NodeID
}

// Encode writes the 20-byte header into dst (which must be at least 20 bytes).
func (h *Header) Encode(dst []byte) error {
	if len(dst) < OverlayHeaderSize {
		return ErrPacketTooShort
	}
	dst[0] = MagicByte
	dst[1] = ((h.Version & 0x0F) << 4) | (uint8(h.Type) & 0x0F)
	dst[2] = h.TTL
	dst[3] = h.Flags
	binary.BigEndian.PutUint64(dst[4:12], uint64(h.SrcNodeID))
	binary.BigEndian.PutUint64(dst[12:20], uint64(h.DstNodeID))
	return nil
}

// DecodeHeader parses the 20-byte Overlay Header without copying the payload.
func DecodeHeader(raw []byte) (Header, error) {
	var h Header
	if len(raw) < OverlayHeaderSize {
		return h, ErrPacketTooShort
	}
	if len(raw) > MaxPhysicalMTU {
		return h, ErrPacketTooLarge
	}
	if raw[0] != MagicByte {
		return h, ErrInvalidMagic
	}
	h.Magic = raw[0]
	h.Version = (raw[1] >> 4) & 0x0F
	if h.Version != ProtocolVersion {
		return h, ErrInvalidVersion
	}
	h.Type = PacketType(raw[1] & 0x0F)
	h.TTL = raw[2]
	h.Flags = raw[3]
	h.SrcNodeID = NodeID(binary.BigEndian.Uint64(raw[4:12]))
	h.DstNodeID = NodeID(binary.BigEndian.Uint64(raw[12:20]))
	return h, nil
}

// DecrementTTLInPlace performs a zero-copy in-place TTL decrement and sets FlagRelayed
// on a raw packet buffer so a Native Peer can immediately forward it without reallocating.
func DecrementTTLInPlace(raw []byte) (srcID, dstID NodeID, err error) {
	if len(raw) < OverlayHeaderSize {
		return 0, 0, ErrPacketTooShort
	}
	if len(raw) > MaxPhysicalMTU {
		return 0, 0, ErrPacketTooLarge
	}
	if raw[0] != MagicByte {
		return 0, 0, ErrInvalidMagic
	}
	ttl := raw[2]
	if ttl <= 1 {
		return 0, 0, ErrTTLExpired
	}
	raw[2] = ttl - 1
	raw[3] |= FlagRelayed
	srcID = NodeID(binary.BigEndian.Uint64(raw[4:12]))
	dstID = NodeID(binary.BigEndian.Uint64(raw[12:20]))
	return srcID, dstID, nil
}
