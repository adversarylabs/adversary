BINARY := bin/adversary
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= unknown
VERSION_PKG := github.com/adversarylabs/adversary/internal/version
LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: build test verify ci clean sign-dev

# Local builds embed the official-dev public key only (no -tags release).
# Release/CI binaries use: go build -tags release … (official-prod only).
# build does NOT wrap Doppler — anyone can compile without secrets.
build:
	mkdir -p $(dir $(BINARY))
	go build -trimpath -ldflags='$(LDFLAGS)' -o $(BINARY) .

test:
	go test ./...

verify:
	scripts/ci-verify.sh quality
	scripts/ci-verify.sh native

# Run the same authoritative stages used by the required CI aggregate. This is
# intentionally comprehensive and includes networked npm/vulnerability checks.
ci:
	scripts/ci-verify.sh all

# Sign a remote ref with the dev official key (Doppler adversarylabs/dev).
# Usage: make sign-dev REF=localhost:8787/adversarylabs/adversary:0.0.22
# Requires: doppler CLI auth, ADVERSARY login for that registry, built binary.
sign-dev: build
	@test -n "$(REF)" || (echo 'usage: make sign-dev REF=<registry/host/name:tag>' >&2; exit 2)
	doppler run --project adversarylabs --config dev -- \
		$(BINARY) sign-official "$(REF)" --key-id official-dev

clean:
	test "$(BINARY)" = "bin/adversary"
	rm -f -- $(BINARY)
