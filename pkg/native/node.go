// Package native implements the Native Peer SuperNode runtime and provides an ergonomic
// net.Listener / net.Conn style API (`lc.Accept()`, `node.Connect(id)`).
//
// Optimizations included:
//   - Multi-goroutine Worker Pool (sharded by SrcNodeID) for concurrent KCP + E2EE processing
//   - sync.Pool 1200-byte packet buffer recycling for zero-allocation relay forwarding
//   - Dual-stack listeners: Raw UDP socket (Native <-> Native) + WebRTC DataChannel
//     ({ordered: false, maxRetransmits: 0}) for Browser Peers
//   - Built-in 0-RTT Stateless Relay + In-band SIGNALING SDP forwarding + Token Bucket rate limiter
package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/p2p-overlay-net/overlay/pkg/overlay"
)

// Config configures a Native Peer node.
type Config struct {
	LighthouseURL string // e.g., "ws://127.0.0.1:8080/ws"
	UDPListenAddr string // e.g., ":9000" (Raw UDP for Native<->Native)
	WebRTCICEPort int    // Optional HTTP/WS or ICE port
	NetworkSecret string // Shared cluster key for 0-RTT E2EE derivation
	WorkerShards  int    // Number of parallel worker goroutines (defaults to runtime.NumCPU())
	IsSuperNode   bool   // True for backend Native Peers (enables stateless relay + signaling router)
}

// Conn represents an accepted or dialed reliable KCP + E2EE P2P stream (`c = lc.Accept()`).
// Implements net.Conn semantics (`Read`, `Write`, `Close`, `RemoteNodeID`).
type Conn struct {
	localID    overlay.NodeID
	remoteID   overlay.NodeID
	conv       uint32
	kcp        *overlay.KCPSession
	e2ee       *overlay.E2EESession
	router     *overlay.Router
	recvCh     chan []byte
	readBuf    []byte
	closed     atomic.Bool
	closeCh    chan struct{}
	closeOnce  sync.Once
}

func newConn(localID, remoteID overlay.NodeID, conv uint32, router *overlay.Router, secret string) (*Conn, error) {
	e2ee, err := overlay.NewZeroRTTSession(localID, remoteID, secret)
	if err != nil {
		return nil, err
	}
	c := &Conn{
		localID:  localID,
		remoteID: remoteID,
		conv:     conv,
		e2ee:     e2ee,
		router:   router,
		recvCh:   make(chan []byte, 256),
		closeCh:  make(chan struct{}),
	}
	c.kcp = overlay.NewKCPSession(conv, func(kcpFrame []byte) {
		c.sendEncryptedKCPFrame(kcpFrame)
	})
	return c, nil
}

func (c *Conn) sendEncryptedKCPFrame(kcpFrame []byte) {
	if c.closed.Load() {
		return
	}
	link, _, err := c.router.SelectLink(c.remoteID)
	if err != nil {
		return
	}
	// Update SCTP/transport backpressure valve before sending
	c.kcp.SetBackpressure(link.BufferedAmount())

	cipherPayload, err := c.e2ee.Seal(c.localID, c.remoteID, kcpFrame)
	if err != nil {
		return
	}
	pkt := getPacketBuffer(overlay.OverlayHeaderSize + len(cipherPayload))
	defer putPacketBuffer(pkt)

	hdr := overlay.Header{
		Magic:     overlay.MagicByte,
		Version:   overlay.ProtocolVersion,
		Type:      overlay.PacketTypeKCPData,
		TTL:       overlay.DefaultTTL,
		Flags:     overlay.FlagEncrypted,
		SrcNodeID: c.localID,
		DstNodeID: c.remoteID,
	}
	_ = hdr.Encode(pkt[:overlay.OverlayHeaderSize])
	copy(pkt[overlay.OverlayHeaderSize:], cipherPayload)
	_ = link.SendRaw(pkt)
}

// RemoteNodeID returns the 64-bit cryptographic NodeID of the remote peer.
func (c *Conn) RemoteNodeID() overlay.NodeID { return c.remoteID }

// Write sends data reliably over the KCP ARQ + E2EE channel.
func (c *Conn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	// Split writes larger than 64KB into chunks that fit comfortably in KCP's window
	total := 0
	const maxChunk = overlay.MaxKCPUserPayload * 32
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxChunk {
			chunk = b[:maxChunk]
		}
		if err := c.kcp.Send(chunk); err != nil {
			return total, err
		}
		c.kcp.Flush(nowMillis())
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

// Read reads the next reassembled message or byte stream chunk from the KCP session.
func (c *Conn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	select {
	case msg, ok := <-c.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, msg)
		if n < len(msg) {
			c.readBuf = msg[n:]
		}
		return n, nil
	case <-c.closeCh:
		return 0, io.EOF
	}
}

// Close closes the virtual KCP connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeCh)
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr                { return overlayAddr(c.localID) }
func (c *Conn) RemoteAddr() net.Addr               { return overlayAddr(c.remoteID) }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type overlayAddr overlay.NodeID

func (a overlayAddr) Network() string { return "p2p-overlay" }
func (a overlayAddr) String() string  { return overlay.NodeID(a).String() }

// packetPool recycles 1200-byte MTU buffers across all UDP and WebRTC read loops.
var packetPool = sync.Pool{
	New: func() any {
		buf := make([]byte, overlay.MaxPhysicalMTU)
		return &buf
	},
}

func getPacketBuffer(size int) []byte {
	bufPtr := packetPool.Get().(*[]byte)
	return (*bufPtr)[:size]
}

func putPacketBuffer(b []byte) {
	if cap(b) >= overlay.MaxPhysicalMTU {
		full := b[:overlay.MaxPhysicalMTU]
		packetPool.Put(&full)
	}
}

type inboundFrame struct {
	raw  []byte
	from overlay.TransportLink
}

// Listener is the Native Peer P2P node and stream listener (`lc = native.Listen(cfg)`).
type Listener struct {
	cfg        Config
	identity   *overlay.CryptoIdentity
	router     *overlay.Router
	udpConn    *net.UDPConn
	wsConn     *websocket.Conn
	wsMu       sync.Mutex

	connsMu    sync.RWMutex
	conns      map[overlay.NodeID]*Conn
	acceptCh   chan *Conn

	workerChs  []chan inboundFrame
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// Listen initializes a Native Peer node, generates its Ed25519 Crypto-ID, starts the
// Raw UDP socket + sharded multi-goroutine worker pool + KCP background ticker, and
// registers with the Lighthouse server if configured.
//
// Usage is as simple as:
//
//	lc, err := native.Listen(cfg)
//	conn, err := lc.Accept()
func Listen(cfg Config) (*Listener, error) {
	if cfg.WorkerShards <= 0 {
		cfg.WorkerShards = runtime.NumCPU()
		if cfg.WorkerShards < 2 {
			cfg.WorkerShards = 2
		}
	}
	if cfg.NetworkSecret == "" {
		cfg.NetworkSecret = "default-p2p-overlay-cluster-secret"
	}

	id, err := overlay.GenerateIdentity()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		cfg:       cfg,
		identity:  id,
		conns:     make(map[overlay.NodeID]*Conn),
		acceptCh:  make(chan *Conn, 128),
		workerChs: make([]chan inboundFrame, cfg.WorkerShards),
		ctx:       ctx,
		cancel:    cancel,
	}

	l.router = overlay.NewRouter(id.NodeID, cfg.IsSuperNode, l.initiateBackgroundHolePunch)

	for i := 0; i < cfg.WorkerShards; i++ {
		l.workerChs[i] = make(chan inboundFrame, 1024)
		l.wg.Add(1)
		go l.runWorkerShard(i, l.workerChs[i])
	}

	if cfg.UDPListenAddr != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.UDPListenAddr)
		if err != nil {
			cancel()
			return nil, err
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			cancel()
			return nil, err
		}
		_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)
		l.udpConn = udpConn

		l.wg.Add(1)
		go l.readUDPLoop()
	}

	// Start 10ms high-precision KCP update ticker
	l.wg.Add(1)
	go l.kcpUpdateTicker()

	// Connect to Lighthouse if URL provided
	if cfg.LighthouseURL != "" {
		go l.maintainLighthouseConnection()
	}

	return l, nil
}

// NodeID returns this Native Peer's 64-bit Crypto-ID.
func (l *Listener) NodeID() overlay.NodeID {
	return l.identity.NodeID
}

// UDPAddr returns the local Raw UDP address if listening.
func (l *Listener) UDPAddr() net.Addr {
	if l.udpConn == nil {
		return nil
	}
	return l.udpConn.LocalAddr()
}

// Accept waits for and returns the next incoming P2P KCP connection to this node (`lc.Accept()`).
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c, ok := <-l.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Connect establishes a 0-RTT KCP stream to remoteID (`c, err := lc.Connect(remoteID)`).
// Data flows immediately via any available SuperNode relay while background hole punching
// upgrades the route to direct UDP or WebRTC.
func (l *Listener) Connect(remoteID overlay.NodeID) (*Conn, error) {
	l.connsMu.Lock()
	if existing, ok := l.conns[remoteID]; ok && !existing.closed.Load() {
		l.connsMu.Unlock()
		return existing, nil
	}
	conv := uint32(l.identity.NodeID^remoteID) & 0x7FFFFFFF
	if conv == 0 {
		conv = 1
	}
	c, err := newConn(l.identity.NodeID, remoteID, conv, l.router, l.cfg.NetworkSecret)
	if err != nil {
		l.connsMu.Unlock()
		return nil, err
	}
	l.conns[remoteID] = c
	l.connsMu.Unlock()
	return c, nil
}

// AddDirectUDPLink registers a known Native Peer's Raw UDP endpoint for direct Native<->Native routing.
func (l *Listener) AddDirectUDPLink(remoteID overlay.NodeID, remoteUDPAddr string) error {
	if l.udpConn == nil {
		return errors.New("native: local UDP listener not enabled")
	}
	raddr, err := net.ResolveUDPAddr("udp", remoteUDPAddr)
	if err != nil {
		return err
	}
	link := &udpTransportLink{
		conn:     l.udpConn,
		raddr:    raddr,
		remoteID: remoteID,
	}
	l.router.UpgradeToDirect(remoteID, link)
	if l.cfg.IsSuperNode {
		l.router.RegisterRelayRoute(remoteID, link)
	}
	return nil
}

// SetDefaultUDPRelay configures a Native Peer SuperNode UDP address as the 0-RTT default relay.
func (l *Listener) SetDefaultUDPRelay(superNodeID overlay.NodeID, superNodeUDPAddr string) error {
	if l.udpConn == nil {
		return errors.New("native: local UDP listener not enabled")
	}
	raddr, err := net.ResolveUDPAddr("udp", superNodeUDPAddr)
	if err != nil {
		return err
	}
	link := &udpTransportLink{
		conn:     l.udpConn,
		raddr:    raddr,
		remoteID: superNodeID,
	}
	l.router.SetDefaultRelay(link)
	return nil
}

// AttachWebRTCDataChannel binds a browser or peer's unreliable WebRTC DataChannel
// (`ordered: false, maxRetransmits: 0`) into the Overlay Router and sharded Worker Pool.
func (l *Listener) AttachWebRTCDataChannel(remoteID overlay.NodeID, dc WebRTCDataChannelAdapter) {
	link := &rtcTransportLink{
		remoteID: remoteID,
		dc:       dc,
	}
	l.router.UpgradeToDirect(remoteID, link)
	if l.cfg.IsSuperNode {
		l.router.RegisterRelayRoute(remoteID, link)
	}
}

// IngestRawPacket feeds a raw <=1200-byte packet from any transport (WebRTC DataChannel or UDP)
// into the sharded worker pool.
func (l *Listener) IngestRawPacket(raw []byte, link overlay.TransportLink) {
	if len(raw) < overlay.OverlayHeaderSize || len(raw) > overlay.MaxPhysicalMTU {
		return
	}
	srcID := overlay.NodeID(binary.BigEndian.Uint64(raw[4:12]))
	cp := getPacketBuffer(len(raw))
	copy(cp, raw)
	shard := int(uint64(srcID) % uint64(len(l.workerChs)))
	select {
	case l.workerChs[shard] <- inboundFrame{raw: cp, from: link}:
	default:
		putPacketBuffer(cp)
	}
}

// Close shuts down the Native Peer listener and all active sessions.
func (l *Listener) Close() error {
	l.cancel()
	if l.udpConn != nil {
		_ = l.udpConn.Close()
	}
	l.wsMu.Lock()
	if l.wsConn != nil {
		_ = l.wsConn.Close()
	}
	l.wsMu.Unlock()
	l.wg.Wait()
	return nil
}

func (l *Listener) readUDPLoop() {
	defer l.wg.Done()
	for {
		buf := getPacketBuffer(overlay.MaxPhysicalMTU)
		n, raddr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			putPacketBuffer(buf)
			select {
			case <-l.ctx.Done():
				return
			default:
				continue
			}
		}
		if n < overlay.OverlayHeaderSize {
			putPacketBuffer(buf)
			continue
		}
		pkt := buf[:n]
		srcID := overlay.NodeID(binary.BigEndian.Uint64(pkt[4:12]))
		link := &udpTransportLink{
			conn:     l.udpConn,
			raddr:    raddr,
			remoteID: srcID,
		}
		shard := int(uint64(srcID) % uint64(len(l.workerChs)))
		select {
		case l.workerChs[shard] <- inboundFrame{raw: pkt, from: link}:
		default:
			putPacketBuffer(buf)
		}
	}
}

func (l *Listener) runWorkerShard(_ int, ch <-chan inboundFrame) {
	defer l.wg.Done()
	for {
		select {
		case frame := <-ch:
			l.processInboundFrame(frame)
			putPacketBuffer(frame.raw)
		case <-l.ctx.Done():
			return
		}
	}
}

func (l *Listener) processInboundFrame(frame inboundFrame) {
	hdr, err := overlay.DecodeHeader(frame.raw)
	if err != nil {
		return
	}

	// Learn reverse route from direct sender if not relayed
	if (hdr.Flags & overlay.FlagRelayed) == 0 && frame.from != nil {
		l.router.UpgradeToDirect(hdr.SrcNodeID, frame.from)
	} else if frame.from != nil {
		l.router.RegisterRelayRoute(hdr.SrcNodeID, frame.from)
	}

	// Zero-copy stateless relay check if destination is another peer
	deliverLocal, err := l.router.ForwardOrDeliver(frame.raw, time.Now())
	if err != nil || !deliverLocal {
		return
	}

	payload := frame.raw[overlay.OverlayHeaderSize:]

	switch hdr.Type {
	case overlay.PacketTypeKCPData:
		conn, isNew := l.getOrCreateConn(hdr.SrcNodeID)
		if conn == nil {
			return
		}
		plainKCP, err := conn.e2ee.Open(hdr.SrcNodeID, l.identity.NodeID, payload)
		if err != nil {
			return
		}
		if err := conn.kcp.Input(plainKCP, nowMillis()); err != nil {
			return
		}
		for {
			msg := conn.kcp.Recv()
			if msg == nil {
				break
			}
			select {
			case conn.recvCh <- msg:
			default:
			}
		}
		if isNew {
			select {
			case l.acceptCh <- conn:
			default:
			}
		}

	case overlay.PacketTypeSignaling:
		env, err := overlay.UnpackSignalingPacket(payload, hdr.Flags)
		if err == nil && env.Action == "udp_probe" && env.UDPAddr != "" {
			_ = l.AddDirectUDPLink(hdr.SrcNodeID, env.UDPAddr)
		}

	case overlay.PacketTypePingPong:
		if (hdr.Flags & overlay.FlagPong) == 0 && frame.from != nil {
			// Echo back PONG
			reply := getPacketBuffer(len(frame.raw))
			defer putPacketBuffer(reply)
			replyHdr := overlay.Header{
				Magic:     overlay.MagicByte,
				Version:   overlay.ProtocolVersion,
				Type:      overlay.PacketTypePingPong,
				TTL:       overlay.DefaultTTL,
				Flags:     overlay.FlagPong,
				SrcNodeID: l.identity.NodeID,
				DstNodeID: hdr.SrcNodeID,
			}
			_ = replyHdr.Encode(reply[:overlay.OverlayHeaderSize])
			copy(reply[overlay.OverlayHeaderSize:], payload)
			_ = frame.from.SendRaw(reply)
		}
	}
}

func (l *Listener) getOrCreateConn(remoteID overlay.NodeID) (*Conn, bool) {
	l.connsMu.RLock()
	c, ok := l.conns[remoteID]
	l.connsMu.RUnlock()
	if ok && !c.closed.Load() {
		return c, false
	}

	l.connsMu.Lock()
	defer l.connsMu.Unlock()
	if c, ok = l.conns[remoteID]; ok && !c.closed.Load() {
		return c, false
	}
	conv := uint32(l.identity.NodeID^remoteID) & 0x7FFFFFFF
	if conv == 0 {
		conv = 1
	}
	c, err := newConn(l.identity.NodeID, remoteID, conv, l.router, l.cfg.NetworkSecret)
	if err != nil {
		return nil, false
	}
	l.conns[remoteID] = c
	return c, true
}

func (l *Listener) kcpUpdateTicker() {
	defer l.wg.Done()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := nowMillis()
			l.connsMu.RLock()
			for _, c := range l.conns {
				if !c.closed.Load() {
					c.kcp.Update(now)
				}
			}
			l.connsMu.RUnlock()
		case <-l.ctx.Done():
			return
		}
	}
}

func (l *Listener) initiateBackgroundHolePunch(targetID overlay.NodeID) {
	if l.udpConn == nil {
		return
	}
	env := overlay.SignalingEnvelope{
		Action:  "udp_probe",
		UDPAddr: l.udpConn.LocalAddr().String(),
	}
	pkt, err := overlay.PackSignalingPacket(l.identity.NodeID, targetID, env)
	if err != nil {
		return
	}
	link, _, err := l.router.SelectLink(targetID)
	if err == nil && link != nil {
		_ = link.SendRaw(pkt)
	}
}

func (l *Listener) maintainLighthouseConnection() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		conn, _, err := websocket.DefaultDialer.Dial(l.cfg.LighthouseURL, http.Header{})
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		l.wsMu.Lock()
		l.wsConn = conn
		l.wsMu.Unlock()

		udpAddr := ""
		if l.udpConn != nil {
			udpAddr = l.udpConn.LocalAddr().String()
		}
		reg := map[string]any{
			"type":     "register",
			"node_id":  l.identity.NodeID.String(),
			"role":     "supernode",
			"udp_addr": udpAddr,
		}
		_ = conn.WriteJSON(reg)

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			var evt map[string]any
			if json.Unmarshal(msg, &evt) == nil {
				if evt["type"] == "seeds" {
					log.Printf("[NativePeer %s] Received seed list from Lighthouse", l.identity.NodeID)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// WebRTCDataChannelAdapter abstracts a Pion or Browser WebRTC DataChannel configured with
// ordered=false and maxRetransmits=0.
type WebRTCDataChannelAdapter interface {
	Send(data []byte) error
	BufferedAmount() uint64
	Close() error
}

type udpTransportLink struct {
	conn     *net.UDPConn
	raddr    *net.UDPAddr
	remoteID overlay.NodeID
}

func (u *udpTransportLink) ID() string                 { return fmt.Sprintf("udp://%s", u.raddr.String()) }
func (u *udpTransportLink) RemoteNodeID() overlay.NodeID { return u.remoteID }
func (u *udpTransportLink) Type() overlay.LinkType     { return overlay.LinkTypeDirectUDP }
func (u *udpTransportLink) BufferedAmount() int        { return 0 }
func (u *udpTransportLink) RTT() time.Duration         { return 5 * time.Millisecond }
func (u *udpTransportLink) Close() error               { return nil }
func (u *udpTransportLink) SendRaw(pkt []byte) error {
	_, err := u.conn.WriteToUDP(pkt, u.raddr)
	return err
}

type rtcTransportLink struct {
	remoteID overlay.NodeID
	dc       WebRTCDataChannelAdapter
}

func (r *rtcTransportLink) ID() string                 { return fmt.Sprintf("rtc://%s", r.remoteID.String()) }
func (r *rtcTransportLink) RemoteNodeID() overlay.NodeID { return r.remoteID }
func (r *rtcTransportLink) Type() overlay.LinkType     { return overlay.LinkTypeDirectRTC }
func (r *rtcTransportLink) BufferedAmount() int        { return int(r.dc.BufferedAmount()) }
func (r *rtcTransportLink) RTT() time.Duration         { return 10 * time.Millisecond }
func (r *rtcTransportLink) Close() error               { return r.dc.Close() }
func (r *rtcTransportLink) SendRaw(pkt []byte) error   { return r.dc.Send(pkt) }

var processStart = time.Now()

func nowMillis() uint32 {
	return uint32(time.Since(processStart).Milliseconds())
}
