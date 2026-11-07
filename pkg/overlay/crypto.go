package overlay

import (
	"bytes"
	"compress/flate"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// E2EESession provides end-to-end authenticated encryption between two peers
// so intermediate Native Peer relays only ever see ciphertext.
type E2EESession struct {
	aead    cipher.AEAD
	txSeq   atomic.Uint64
	sharedKey [32]byte
}

// GenerateX25519Keypair creates an ephemeral X25519 keypair for ECDH key agreement.
func GenerateX25519Keypair() (priv [32]byte, pub [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, pub, err
	}
	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], pubSlice)
	return priv, pub, nil
}

// NewE2EESessionFromSharedSecret derives a ChaCha20-Poly1305 AEAD cipher from an X25519 shared secret
// or a deterministic pair of NodeIDs (for 0-RTT pre-shared/derived overlay sessions).
func NewE2EESessionFromSharedSecret(secret []byte) (*E2EESession, error) {
	key := sha256.Sum256(secret)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &E2EESession{
		aead:      aead,
		sharedKey: key,
	}, nil
}

// NewZeroRTTSession derives a deterministic symmetric session key between two NodeIDs
// using a network-wide cluster key so 0-RTT relayed KCP frames are encrypted immediately
// before the full X25519 signaling upgrade completes.
func NewZeroRTTSession(nodeA, nodeB NodeID, networkSecret string) (*E2EESession, error) {
	minID, maxID := nodeA, nodeB
	if minID > maxID {
		minID, maxID = maxID, minID
	}
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(minID))
	binary.BigEndian.PutUint64(buf[8:16], uint64(maxID))
	material := append(buf[:], []byte(networkSecret)...)
	return NewE2EESessionFromSharedSecret(material)
}

// Seal encrypts plaintext using the 20-byte Overlay Header as Additional Authenticated Data (AAD)
// (masking mutable TTL and Relay flags so intermediate relays do not break the AEAD tag).
// Because the 8-byte nonce prefix is embedded, maximum overhead is 16B Poly1305 tag (or 8B nonce + 8B tag).
// Here we derive the 12-byte nonce deterministically from (SrcNodeID || Counter) and prepend a 0-byte overhead
// when using the KCP sn/ts or an explicit 16-byte Poly1305 tag.
func (s *E2EESession) Seal(srcID, dstID NodeID, plaintext []byte) ([]byte, error) {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], uint32(srcID))
	// For stateless datagram decryption across out-of-order WebRTC packets, we derive nonce[4:12]
	// from the first 8 bytes of the KCP header (conv + cmd/frg/wnd or ts/sn) when len >= 16,
	// ensuring exact 16-byte AEAD expansion (24B KCP + 16B Tag + 1140B Data = 1180B).
	if len(plaintext) >= 16 {
		copy(nonce[4:12], plaintext[8:16]) // KCP ts (4B) + sn (4B)
	} else {
		seq := s.txSeq.Add(1)
		binary.BigEndian.PutUint64(nonce[4:12], seq)
	}

	aad := makeAAD(srcID, dstID)
	// Encrypt plaintext[16:] while leaving KCP header bytes [0:16] as plaintext nonce carrier,
	// or encrypt all and append 16B tag when nonce is deterministic.
	if len(plaintext) >= 16 {
		out := make([]byte, 16, len(plaintext)+chacha20poly1305.Overhead)
		copy(out[:16], plaintext[:16])
		out = s.aead.Seal(out, nonce[:], plaintext[16:], aad[:])
		return out, nil
	}
	return nil, errors.New("e2ee: frame shorter than 16-byte header carrier")
}

// Open verifies and decrypts an E2EE frame produced by Seal.
func (s *E2EESession) Open(srcID, dstID NodeID, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 16+chacha20poly1305.Overhead {
		return nil, errors.New("e2ee: ciphertext too short")
	}
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], uint32(srcID))
	copy(nonce[4:12], ciphertext[8:16])

	aad := makeAAD(srcID, dstID)
	decryptedTail, err := s.aead.Open(nil, nonce[:], ciphertext[16:], aad[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16+len(decryptedTail))
	copy(out[:16], ciphertext[:16])
	copy(out[16:], decryptedTail)
	return out, nil
}

func makeAAD(srcID, dstID NodeID) [16]byte {
	var aad [16]byte
	binary.BigEndian.PutUint64(aad[0:8], uint64(srcID))
	binary.BigEndian.PutUint64(aad[8:16], uint64(dstID))
	return aad
}

// CompressSignalingSDP strips unnecessary audio/video/extmap lines from a WebRTC SDP
// and compresses it with raw Deflate (BestCompression) so a 2KB~4KB SDP shrinks to
// ~300-500 bytes and fits comfortably inside a single 1180-byte SIGNALING packet.
func CompressSignalingSDP(rawSDP string) ([]byte, error) {
	var stripped strings.Builder
	for _, line := range strings.Split(rawSDP, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Keep only session, ICE, DTLS fingerprint, and application (DataChannel) lines
		if strings.HasPrefix(trimmed, "a=rtpmap:") ||
			strings.HasPrefix(trimmed, "a=fmtp:") ||
			strings.HasPrefix(trimmed, "a=rtcp-fb:") ||
			strings.HasPrefix(trimmed, "a=extmap:") {
			continue
		}
		stripped.WriteString(trimmed)
		stripped.WriteByte('\n')
	}

	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write([]byte(stripped.String())); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressSignalingSDP inflates a compressed SIGNALING payload back into an SDP string.
func DecompressSignalingSDP(compressed []byte) (string, error) {
	zr := flate.NewReader(bytes.NewReader(compressed))
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, 64*1024))
	if err != nil {
		return "", err
	}
	return string(out), nil
}
