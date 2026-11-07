.PHONY: all build-lighthouse build-native build-wasm test clean package

BINARY_DIR=bin
VERSION ?= v0.1.0

all: build-lighthouse build-native build-wasm

build-lighthouse:
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY_DIR)/lighthouse ./cmd/lighthouse

build-native:
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY_DIR)/native-peer ./cmd/native-peer

build-wasm:
	@mkdir -p web-sdk/wasm
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web-sdk/wasm/overlay.wasm ./cmd/wasm-core
	@cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" web-sdk/wasm/ 2>/dev/null || true

test:
	go test -v -race ./pkg/...

clean:
	rm -rf $(BINARY_DIR) web-sdk/wasm/*.wasm
