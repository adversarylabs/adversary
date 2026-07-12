BINARY := bin/adversary
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= unknown
VERSION_PKG := github.com/adversarylabs/adversary/internal/version
LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: build test verify ci clean

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

clean:
	test "$(BINARY)" = "bin/adversary"
	rm -f -- $(BINARY)
