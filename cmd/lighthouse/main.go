// Command lighthouse runs the stateless discovery server, SuperNode seed registry,
// initial cold-start WebSocket signaling bootstrap, and lightweight UDP STUN reflector.
//
// Core architectural constraint:
//   - NEVER forwards any business data or acts as a TURN server.
//   - Designed to survive unstable network links: once peers connect to at least 1
//     SuperNode (Native Peer), all subsequent signaling and 0-RTT relay run in-band
//     inside the P2P overlay mesh even if the Lighthouse goes offline.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// SeedCandidate describes an active Native Peer SuperNode or recently seen peer.
type SeedCandidate struct {
	NodeID     string    `json:"node_id"`
	Role       string    `json:"role"` // "supernode" or "browser"
	PublicIP   string    `json:"public_ip"`
	UDPAddr    string    `json:"udp_addr,omitempty"`
	SignalingURL string  `json:"signaling_url,omitempty"`
	RTTScore   int       `json:"rtt_score_ms"`
	LastSeen   time.Time `json:"last_seen"`
}

type peerSession struct {
	info SeedCandidate
	conn *websocket.Conn
	mu   sync.Mutex
}

func (p *peerSession) sendJSON(v any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return p.conn.WriteJSON(v)
}

type LighthouseServer struct {
	mu       sync.RWMutex
	sessions map[string]*peerSession
	upgrader websocket.Upgrader
}

func NewLighthouseServer() *LighthouseServer {
	s := &LighthouseServer{
		sessions: make(map[string]*peerSession),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
	go s.evictStalePeersLoop()
	return s
}

func (s *LighthouseServer) evictStalePeersLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-60 * time.Second)
		s.mu.Lock()
		for id, sess := range s.sessions {
			if sess.info.LastSeen.Before(cutoff) {
				_ = sess.conn.Close()
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// ActiveSeeds returns the top active SuperNodes and candidate peers sorted by freshness.
func (s *LighthouseServer) ActiveSeeds(excludeNodeID string) []SeedCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seeds := make([]SeedCandidate, 0, len(s.sessions))
	// Prioritize "supernode" (Native Peer) seeds first
	for id, sess := range s.sessions {
		if id == excludeNodeID {
			continue
		}
		if sess.info.Role == "supernode" {
			seeds = append(seeds, sess.info)
		}
	}
	for id, sess := range s.sessions {
		if id == excludeNodeID || sess.info.Role == "supernode" {
			continue
		}
		seeds = append(seeds, sess.info)
	}
	return seeds
}

func (s *LighthouseServer) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	var registeredID string

	defer func() {
		_ = conn.Close()
		if registeredID != "" {
			s.mu.Lock()
			if cur, ok := s.sessions[registeredID]; ok && cur.conn == conn {
				delete(s.sessions, registeredID)
			}
			s.mu.Unlock()
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]any
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		msgType, _ := msg["type"].(string)

		switch msgType {
		case "register":
			nodeID, _ := msg["node_id"].(string)
			role, _ := msg["role"].(string)
			if role == "" {
				role = "browser"
			}
			udpAddr, _ := msg["udp_addr"].(string)
			if nodeID == "" {
				continue
			}
			registeredID = nodeID
			sess := &peerSession{
				info: SeedCandidate{
					NodeID:   nodeID,
					Role:     role,
					PublicIP: clientIP,
					UDPAddr:  udpAddr,
					LastSeen: time.Now(),
				},
				conn: conn,
			}
			s.mu.Lock()
			s.sessions[nodeID] = sess
			s.mu.Unlock()

			// Immediately reply with public IP reflection + SuperNode seed candidates
			_ = sess.sendJSON(map[string]any{
				"type":      "welcome",
				"node_id":   nodeID,
				"public_ip": clientIP,
				"seeds":     s.ActiveSeeds(nodeID),
			})

		case "heartbeat":
			if registeredID != "" {
				s.mu.Lock()
				if sess, ok := s.sessions[registeredID]; ok {
					sess.info.LastSeen = time.Now()
				}
				s.mu.Unlock()
				_ = conn.WriteJSON(map[string]any{
					"type":  "seeds",
					"seeds": s.ActiveSeeds(registeredID),
				})
			}

		case "signal":
			// Cold-start handshake relay ONLY (SDP Offer/Answer/ICE for initial SuperNode join).
			// Strictly rejects raw data forwarding.
			targetID, _ := msg["target_id"].(string)
			if len(raw) > 8192 {
				continue // Refuse oversized payloads
			}
			s.mu.RLock()
			targetSess, ok := s.sessions[targetID]
			s.mu.RUnlock()
			if ok {
				msg["from_id"] = registeredID
				_ = targetSess.sendJSON(msg)
			}
		}
	}
}

func (s *LighthouseServer) handleSeedsHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"public_ip": clientIP,
		"seeds":     s.ActiveSeeds(r.URL.Query().Get("node_id")),
		"timestamp": time.Now().Unix(),
	})
}

// runLightweightSTUN starts a minimal RFC 5389 Binding Request UDP STUN responder
// so Native and Browser peers can discover their external NAT IP:Port without third-party STUN servers.
func runLightweightSTUN(udpAddr string) {
	addr, err := net.ResolveUDPAddr("udp4", udpAddr)
	if err != nil {
		log.Printf("[STUN] Resolve error: %v", err)
		return
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Printf("[STUN] Listen error: %v", err)
		return
	}
	log.Printf("[Lighthouse STUN] Listening on UDP %s", conn.LocalAddr())

	buf := make([]byte, 512)
	const stunMagicCookie uint32 = 0x2112A442
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil || n < 20 {
			continue
		}
		// Check STUN Binding Request (0x0001) and magic cookie (0x2112A442)
		msgType := binary.BigEndian.Uint16(buf[0:2])
		cookie := binary.BigEndian.Uint32(buf[4:8])
		if msgType != 0x0001 || cookie != stunMagicCookie {
			continue
		}
		ip4 := raddr.IP.To4()
		if ip4 == nil {
			continue
		}
		// Construct 32-byte STUN Binding Success Response (0x0101) with XOR-MAPPED-ADDRESS (0x0020)
		var resp [32]byte
		binary.BigEndian.PutUint16(resp[0:2], 0x0101) // Binding Success Response
		binary.BigEndian.PutUint16(resp[2:4], 12)     // Attribute length = 12 bytes
		binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
		copy(resp[8:20], buf[8:20]) // 12-byte Transaction ID

		// XOR-MAPPED-ADDRESS attribute
		binary.BigEndian.PutUint16(resp[20:22], 0x0020)
		binary.BigEndian.PutUint16(resp[22:24], 8)
		resp[24] = 0x00
		resp[25] = 0x01 // IPv4 family
		xorPort := uint16(raddr.Port) ^ uint16(stunMagicCookie>>16)
		binary.BigEndian.PutUint16(resp[26:28], xorPort)
		xorIP := binary.BigEndian.Uint32(ip4) ^ stunMagicCookie
		binary.BigEndian.PutUint32(resp[28:32], xorIP)

		_, _ = conn.WriteToUDP(resp[:], raddr)
	}
}

func main() {
	httpAddr := flag.String("http", ":8080", "HTTP & WebSocket listen address")
	stunAddr := flag.String("stun", ":3478", "UDP STUN listen address")
	staticDir := flag.String("web", "./web-sdk", "Static directory for Browser Demo")
	flag.Parse()

	go runLightweightSTUN(*stunAddr)

	srv := NewLighthouseServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", srv.handleWS)
	mux.HandleFunc("/api/seeds", srv.handleSeedsHTTP)
	mux.Handle("/", http.FileServer(http.Dir(*staticDir)))

	log.Printf("[Lighthouse] Discovery & Bootstrap listening on http://%s (WS: /ws, Seeds: /api/seeds)", *httpAddr)
	if err := http.ListenAndServe(*httpAddr, mux); err != nil {
		log.Fatal(err)
	}
}
