// Command native-peer demonstrates how simple it is to run a Native Peer SuperNode
// or backend service using the `lc = native.Listen()` and `conn = lc.Accept()` API.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/p2p-overlay-net/overlay/pkg/native"
	"github.com/p2p-overlay-net/overlay/pkg/overlay"
)

func main() {
	lighthouseURL := flag.String("lighthouse", "ws://127.0.0.1:8080/ws", "Lighthouse WebSocket URL")
	udpAddr := flag.String("udp", ":0", "Raw UDP listen address for Native<->Native & Relay")
	connectPeerHex := flag.String("connect", "", "Optional target 64-bit NodeID hex to dial")
	connectUDP := flag.String("peer-udp", "", "Optional seed/relay UDP address")
	flag.Parse()

	// 1. Start the Native Peer listener (spawns sharded Worker Pool + Raw UDP + 0-RTT Relay)
	lc, err := native.Listen(native.Config{
		LighthouseURL: *lighthouseURL,
		UDPListenAddr: *udpAddr,
		IsSuperNode:   true,
	})
	if err != nil {
		log.Fatalf("Failed to start native peer: %v", err)
	}
	defer lc.Close()

	log.Printf("================================================================")
	log.Printf("Native Peer SuperNode Online!")
	log.Printf("  Crypto NodeID : %s", lc.NodeID())
	log.Printf("  Raw UDP Addr  : %s", lc.UDPAddr())
	log.Printf("================================================================")

	// Optional: if a target peer NodeID is passed via -connect, dial it directly (`c = lc.Connect(id)`)
	if *connectPeerHex != "" {
		targetID, err := overlay.ParseNodeID(*connectPeerHex)
		if err != nil {
			log.Fatalf("Invalid target NodeID: %v", err)
		}
		if *connectUDP != "" {
			_ = lc.AddDirectUDPLink(targetID, *connectUDP)
		}
		conn, err := lc.Connect(targetID)
		if err != nil {
			log.Fatalf("Connect error: %v", err)
		}
		_, _ = conn.Write([]byte(fmt.Sprintf("Hello from Native Peer %s!", lc.NodeID())))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err == nil {
			log.Printf("[Client Mode] Received reply from %s: %s", conn.RemoteNodeID(), string(buf[:n]))
		}
		return
	}

	// 2. Accept incoming P2P KCP connections (`conn, err := lc.Accept()`)
	go func() {
		for {
			conn, err := lc.Accept()
			if err != nil {
				return
			}
			log.Printf("[Accept] New KCP+E2EE stream from NodeID=%s", conn.RemoteNodeID())
			go handlePeerStream(conn)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down Native Peer...")
}

func handlePeerStream(conn *native.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Stream %s] Read error: %v", conn.RemoteNodeID(), err)
			}
			return
		}
		msg := string(buf[:n])
		log.Printf("[Stream %s] Recv (%d bytes): %s", conn.RemoteNodeID(), n, msg)

		// Echo response back over KCP + E2EE
		reply := fmt.Sprintf("ACK from SuperNode %s -> %s", conn.LocalAddr(), msg)
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}
