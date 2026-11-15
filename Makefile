BINARY  := hyperion-trace
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
FUZZTIME ?= 30s

.PHONY: build test race fuzz lint audit check clean

# Static, CGO-free binary with a reproducible (trimmed) build path.
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/hyperion-trace

test:
	go test ./...

race:
	go test -race -count=1 ./...

fuzz:
	go test ./internal/checks/   -run '^$$' -fuzz '^FuzzSSHDParsers$$'   -fuzztime $(FUZZTIME)
	go test ./internal/checks/   -run '^$$' -fuzz '^FuzzSudoParsers$$'   -fuzztime $(FUZZTIME)
	go test ./internal/checks/   -run '^$$' -fuzz '^FuzzParseKeyValue$$' -fuzztime $(FUZZTIME)
	go test ./internal/checks/   -run '^$$' -fuzz '^FuzzParseMounts$$'   -fuzztime $(FUZZTIME)
	go test ./internal/report/   -run '^$$' -fuzz '^FuzzSanitize$$'      -fuzztime $(FUZZTIME)
	go test ./internal/platform/ -run '^$$' -fuzz '^FuzzParseEnvFile$$'  -fuzztime $(FUZZTIME)

lint:
	gofmt -l . | (! grep .)
	go vet ./...

# Security analysis: known-vulnerable dependencies, security lint, bug finder.
audit:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

check: lint race

clean:
	rm -rf bin
