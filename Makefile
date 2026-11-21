BINARY  := nulq
PKG     := github.com/dustin04x/nulq
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

GO_FILES := $(shell find . -name '*.go' -not -path './.git/*')

.PHONY: all build test race lint fmt check-fmt vet clean release verify \
	lab-build lab-up lab-status lab-test lab-logs lab-down lab-reset lab-cleanup

all: build

## build: compile a static linux binary for the host architecture
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/nulq

## test: run the unit and integration test suite
test:
	go test ./...

## race: run the test suite under the race detector
race:
	go test -race ./...

## fmt: format all Go sources
fmt:
	@find . -name '*.go' -not -path './.git/*' -print0 | xargs -0 gofmt -w

## check-fmt: fail when any Go source is not gofmt-clean
check-fmt:
	@out=$$(find . -name '*.go' -not -path './.git/*' -print0 | xargs -0 gofmt -l); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

## vet: run go vet
vet:
	go vet ./...

## lint: formatting, vet and staticcheck when available
lint: check-fmt vet
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; skipping (go vet already ran)"; \
	fi

## clean: remove build and release output
clean:
	rm -rf bin dist

## release: cross-compile linux/amd64 and linux/arm64 with checksums
release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" \
		-o dist/$(BINARY)-$(VERSION)-linux-amd64 ./cmd/nulq
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" \
		-o dist/$(BINARY)-$(VERSION)-linux-arm64 ./cmd/nulq
	cd dist && sha256sum $(BINARY)-$(VERSION)-linux-amd64 $(BINARY)-$(VERSION)-linux-arm64 > SHA256SUMS

## verify: check release checksums
verify:
	cd dist && sha256sum -c SHA256SUMS

## lab-build: build the real binary and the pinned Alpine laboratory image
lab-build:
	@lab/scripts/lab-build.sh

## lab-up: start the long-running Alpine target for manual inspection
lab-up:
	@lab/scripts/lab-up.sh

## lab-status: show NULQ laboratory resources and artifacts only
lab-status:
	@lab/scripts/lab-status.sh

## lab-test: run the full isolated assessment, validate JSON and scenarios
lab-test:
	@lab/scripts/lab-test.sh

## lab-logs: show logs for NULQ laboratory containers
lab-logs:
	@lab/scripts/lab-logs.sh

## lab-down: stop laboratory containers and the project network
lab-down:
	@lab/scripts/lab-down.sh

## lab-reset: rebuild the laboratory image from scratch
lab-reset:
	@lab/scripts/lab-reset.sh

## lab-cleanup: remove only NULQ laboratory containers and image
lab-cleanup:
	@lab/scripts/lab-cleanup.sh
