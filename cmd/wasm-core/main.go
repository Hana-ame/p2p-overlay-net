//go:build js && wasm

// Command wasm-core compiles the Go Sans-IO 20-byte Overlay Header + Tuned KCP + E2EE
// protocol core into WebAssembly so Browser Web Workers can run the exact same Go
// protocol state machine alongside the native JS zero-dependency fallback engine.
package main

import (
	"syscall/js"

	"github.com/p2p-overlay-net/overlay/pkg/overlay"
)

func main() {
	id, _ := overlay.GenerateIdentity()
	js.Global().Set("OverlayWasmNodeID", id.NodeID.String())
	select {}
}
