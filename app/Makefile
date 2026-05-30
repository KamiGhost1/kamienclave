SHELL := /bin/bash

BIN_DIR     := bin
PKG         := github.com/kamighost/kamienclave
CMD         := ./cmd/enclave
VERSION     ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo 0.0.0-dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS_PUB := -X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.date=$(DATE)' -X 'main.variant=public'
LDFLAGS_BE  := -s -w -buildid= -X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.date=$(DATE)' -X 'main.variant=backend'

# stamp appends the integrity trailer (sha256 of the body) to a built
# binary. Must run LAST — after garble — so it covers the final bytes.
STAMP := go run ./cmd/stamp

.PHONY: all build build-public build-backend build-backend-plain build-demo build-host tidy lint vet test cover ci fuzz fmt clean

all: build

build: build-public

# Public build: the open `enclave` binary (goja JS path).
build-public:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS_PUB)" -o $(BIN_DIR)/enclave $(CMD)
	$(STAMP) $(BIN_DIR)/enclave

# Dev-only build with the in-process demo subcommand wired in.
build-demo:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -tags demo -trimpath -ldflags "$(LDFLAGS_PUB)" -o $(BIN_DIR)/enclave-demo $(CMD)

# Obfuscated backend build via garble -> the `enclave-vm` binary (bytecode
# mini-VM path). Installed in the dev container; on a host without garble
# run `go install mvdan.cc/garble@latest` first. The `backend` build tag
# flips the policy package into silent-exit mode.
build-backend:
	@mkdir -p $(BIN_DIR)
	@command -v garble >/dev/null || { echo "garble not found in PATH"; exit 1; }
	CGO_ENABLED=0 garble -literals -tiny build -tags backend -trimpath -ldflags "$(LDFLAGS_BE)" -o $(BIN_DIR)/enclave-vm $(CMD)
	$(STAMP) $(BIN_DIR)/enclave-vm

# Same as build-backend but without garble — useful for local smoke tests
# of the backend policy without paying the obfuscation cost.
build-backend-plain:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -tags backend -trimpath -ldflags "$(LDFLAGS_BE)" -o $(BIN_DIR)/enclave-vm-plain $(CMD)
	$(STAMP) $(BIN_DIR)/enclave-vm-plain

# Full-application loader (режим B): fetches and runs a Node app in memory.
build-host:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS_BE)" -o $(BIN_DIR)/enclave-host ./cmd/enclave-host
	$(STAMP) $(BIN_DIR)/enclave-host

tidy:
	go mod tidy

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not found"; exit 1; }
	golangci-lint run ./...

test:
	go test ./...
	go test -tags backend ./...

cover:
	go test -coverprofile=coverage.txt ./... && go tool cover -func=coverage.txt | tail -1

# Fuzz the untrusted-input parsers (network-facing). FUZZTIME overrides
# the per-target budget, e.g. `make fuzz FUZZTIME=2m`.
FUZZTIME ?= 30s
fuzz:
	go test ./runtime/bytecode/ -run=^$$ -fuzz=FuzzDecode$$ -fuzztime=$(FUZZTIME)
	go test ./runtime/bytecode/ -run=^$$ -fuzz=FuzzDecodeEncrypted$$ -fuzztime=$(FUZZTIME)
	go test ./encpkg/ -run=^$$ -fuzz=FuzzOpen$$ -fuzztime=$(FUZZTIME)
	go test ./encpkg/ -run=^$$ -fuzz=FuzzOpenSigned$$ -fuzztime=$(FUZZTIME)

fmt:
	gofmt -s -w .

clean:
	rm -rf $(BIN_DIR)
