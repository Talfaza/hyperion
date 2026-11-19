BINARY  := hyperion-trace
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
FUZZTIME ?= 30s

.PHONY: build test race fuzz lint audit check vm-test vm-test-libvirt clean

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
# All three always run; the target fails at the end if any of them failed.
audit:
	@status=0; \
	echo "== govulncheck"; go run golang.org/x/vuln/cmd/govulncheck@latest ./... || status=1; \
	echo "== gosec"; go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./... || status=1; \
	echo "== staticcheck"; go run honnef.co/go/tools/cmd/staticcheck@latest ./... || status=1; \
	exit $$status

check: lint race

# Cross-distro tests in throwaway Ksar microVMs (needs KVM and ksar; see
# test/vm/vm_test.go). Not part of `make test`: VMs take several minutes and
# the hardened runs download packages from the distro mirrors.
vm-test: build
	HYPERION_BIN=$(CURDIR)/bin/$(BINARY) go test -tags vmtest -count=1 -v -timeout 90m ./test/vm/

# Full-distro tests in libvirt VMs (Ubuntu 24.04, Rocky 9) with real systemd,
# AppArmor/SELinux and firewalls. Needs libvirt (user session), passt and
# ~2 GB for cached cloud images in ~/.cache/hyperion-vm. VMs are deleted
# afterwards.
vm-test-libvirt: build
	HYPERION_BIN=$(CURDIR)/bin/$(BINARY) go test -tags 'vmtest libvirt' -count=1 -v -timeout 90m -run TestLibvirt ./test/vm/

clean:
	rm -rf bin
