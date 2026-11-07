package overlay

import (
	"bytes"
	"testing"
	"time"
)

type mockLink struct {
	id       string
	remoteID NodeID
	linkType LinkType
	sent     [][]byte
	rtt      time.Duration
}

func (m *mockLink) ID() string            { return m.id }
func (m *mockLink) RemoteNodeID() NodeID  { return m.remoteID }
func (m *mockLink) Type() LinkType        { return m.linkType }
func (m *mockLink) BufferedAmount() int   { return 0 }
func (m *mockLink) RTT() time.Duration    { return m.rtt }
func (m *mockLink) Close() error          { return nil }
func (m *mockLink) SendRaw(p []byte) error {
	cp := make([]byte, len(p))
	copy(cp, p)
	m.sent = append(m.sent, cp)
	return nil
}

func TestHeaderEncodeDecodeAndZeroCopyRelay(t *testing.T) {
	idA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	pkt := make([]byte, OverlayHeaderSize+10)
	hdr := Header{
		Magic:     MagicByte,
		Version:   ProtocolVersion,
		Type:      PacketTypeKCPData,
		TTL:       DefaultTTL,
		Flags:     FlagEncrypted,
		SrcNodeID: idA.NodeID,
		DstNodeID: idB.NodeID,
	}
	if err := hdr.Encode(pkt[:OverlayHeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(pkt[OverlayHeaderSize:], []byte("hello-p2p!"))

	decoded, err := DecodeHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SrcNodeID != idA.NodeID || decoded.DstNodeID != idB.NodeID || decoded.Type != PacketTypeKCPData {
		t.Fatalf("unexpected decoded header: %+v", decoded)
	}

	// Test in-place zero-copy TTL decrement
	src, dst, err := DecrementTTLInPlace(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if src != idA.NodeID || dst != idB.NodeID {
		t.Fatalf("unexpected src/dst after TTL decrement")
	}
	decodedAfter, _ := DecodeHeader(pkt)
	if decodedAfter.TTL != DefaultTTL-1 || (decodedAfter.Flags&FlagRelayed) == 0 {
		t.Fatalf("expected TTL=%d and FlagRelayed set, got %+v", DefaultTTL-1, decodedAfter)
	}
}

func TestKCPSessionWithLossAndE2EE(t *testing.T) {
	nodeA := NodeID(0x1111222233334444)
	nodeB := NodeID(0x5555666677778888)

	e2eeA, err := NewZeroRTTSession(nodeA, nodeB, "test-net-key")
	if err != nil {
		t.Fatal(err)
	}
	e2eeB, err := NewZeroRTTSession(nodeB, nodeA, "test-net-key")
	if err != nil {
		t.Fatal(err)
	}

	var wireAtoB [][]byte
	var wireBtoA [][]byte

	kcpA := NewKCPSession(1001, func(frame []byte) {
		cipherFrame, err := e2eeA.Seal(nodeA, nodeB, frame)
		if err != nil {
			t.Fatal(err)
		}
		if len(cipherFrame)+OverlayHeaderSize > MaxPhysicalMTU {
			t.Fatalf("MTU ceiling violated: %d > %d", len(cipherFrame)+OverlayHeaderSize, MaxPhysicalMTU)
		}
		wireAtoB = append(wireAtoB, cipherFrame)
	})

	kcpB := NewKCPSession(1001, func(frame []byte) {
		cipherFrame, err := e2eeB.Seal(nodeB, nodeA, frame)
		if err != nil {
			t.Fatal(err)
		}
		wireBtoA = append(wireBtoA, cipherFrame)
	})

	// Send a 3500-byte payload that spans 4 KCP segments (1140B MSS each)
	largePayload := bytes.Repeat([]byte("KCP-OVER-WEBRTC-"), 220)
	if err := kcpA.Send(largePayload); err != nil {
		t.Fatal(err)
	}

	now := uint32(100)
	kcpA.Update(now)

	// Drop the very first packet to verify ARQ fast retransmit / RTO recovery
	droppedFirst := false
	for step := 0; step < 30; step++ {
		now += 15
		kcpA.Update(now)
		kcpB.Update(now)

		for _, pkt := range wireAtoB {
			if !droppedFirst {
				droppedFirst = true
				continue // simulate packet loss
			}
			plain, err := e2eeB.Open(nodeA, nodeB, pkt)
			if err != nil {
				t.Fatalf("E2EE decrypt failed: %v", err)
			}
			if err := kcpB.Input(plain, now); err != nil {
				t.Fatal(err)
			}
		}
		wireAtoB = wireAtoB[:0]

		for _, pkt := range wireBtoA {
			plain, err := e2eeA.Open(nodeB, nodeA, pkt)
			if err != nil {
				t.Fatal(err)
			}
			if err := kcpA.Input(plain, now); err != nil {
				t.Fatal(err)
			}
		}
		wireBtoA = wireBtoA[:0]

		if got := kcpB.Recv(); got != nil {
			if !bytes.Equal(got, largePayload) {
				t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(got), len(largePayload))
			}
			return
		}
	}
	t.Fatal("KCP failed to recover and reassemble payload within 30 ticks")
}

func TestSeamlessZeroRTTRelayAndHotUpgrade(t *testing.T) {
	nodeA := NodeID(0xAAAA)
	nodeB := NodeID(0xBBBB)
	nodeRelay := NodeID(0xDDDD)

	punchTriggered := make(chan NodeID, 1)
	routerA := NewRouter(nodeA, false, func(target NodeID) {
		punchTriggered <- target
	})

	relayLink := &mockLink{id: "relay-D", remoteID: nodeRelay, linkType: LinkTypeRelay}
	routerA.SetDefaultRelay(relayLink)

	// 1. First packet to B immediately picks Relay D (0ms wait) and triggers background hole punch
	link1, isRelayed, err := routerA.SelectLink(nodeB)
	if err != nil || !isRelayed || link1.ID() != "relay-D" {
		t.Fatalf("expected 0-RTT relay link, got link=%v isRelayed=%v err=%v", link1, isRelayed, err)
	}

	select {
	case target := <-punchTriggered:
		if target != nodeB {
			t.Fatalf("expected hole punch for %v, got %v", nodeB, target)
		}
	case <-time.After(time.Second):
		t.Fatal("expected background hole punch trigger")
	}

	// 2. Simulate background WebRTC DataChannel hole punch succeeding
	directLink := &mockLink{id: "direct-B", remoteID: nodeB, linkType: LinkTypeDirectRTC}
	routerA.UpgradeToDirect(nodeB, directLink)

	// 3. Subsequent packets seamlessly switch to direct link
	link2, isRelayed2, err := routerA.SelectLink(nodeB)
	if err != nil || isRelayed2 || link2.ID() != "direct-B" {
		t.Fatalf("expected upgraded direct link, got link=%v isRelayed=%v err=%v", link2, isRelayed2, err)
	}
}
