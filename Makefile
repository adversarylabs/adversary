BINARY := bin/adversary
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= unknown
VERSION_PKG := github.com/adversarylabs/adversary/internal/version
LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: build test verify clean

build:
	mkdir -p $(dir $(BINARY))
	go build -trimpath -ldflags='$(LDFLAGS)' -o $(BINARY) .

test:
	go test ./...

verify:
	@files="$$(gofmt -l $$(git ls-files '*.go'))"; test -z "$$files" || { printf '%s\n' "$$files" >&2; exit 1; }
	go test ./...
	go vet ./...
	go mod verify

clean:
	test "$(BINARY)" = "bin/adversary"
	rm -f -- $(BINARY)
