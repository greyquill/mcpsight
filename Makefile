# mcpsight — Greyquill Software Private Limited
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG     := github.com/greyquill/mcpsight/internal/buildinfo
LDFLAGS := -s -w -X '$(PKG).Version=$(VERSION)' -X '$(PKG).Commit=$(COMMIT)'

.PHONY: all build build-index test vet fmt tidy clean preview fixture

all: vet test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mcpsight ./cmd/mcpsight

build-index:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mcpsight-index ./cmd/mcpsight-index

# Serve the static Registry Security Index and open it in a browser (no database).
preview: build-index
	./bin/mcpsight-index preview

# Serve the fixture personas over HTTP on 127.0.0.1:8931, for scanning remote
# targets by hand on any machine. See testdata/servers/README.md.
fixture:
	go run ./testdata/servers/http-fixture

test:
	go test ./...

vet:
	go vet ./... ./testdata/servers/http-fixture

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin dist
