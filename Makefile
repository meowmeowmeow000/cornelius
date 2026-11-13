BINARY_DAEMON := bin/cornelius
BINARY_TUI    := bin/cornelius-tui
ARCH_INCLUDE  := /usr/include/$(shell uname -m)-linux-gnu

.PHONY: all ebpf build tui test vet install-caps clean

all: build tui

ebpf:
	C_INCLUDE_PATH="$(ARCH_INCLUDE)" go generate ./internal/bpf

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY_DAEMON) ./cmd/cornelius

tui:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY_TUI) ./cmd/tui

test:
	go test ./...

vet:
	go vet ./...

install-caps: build
	sudo setcap cap_net_raw,cap_net_admin,cap_bpf+ep $(BINARY_DAEMON)

clean:
	rm -rf bin/
