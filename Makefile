PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: all build test clean install uninstall doctor

VERSION ?= $(shell cat VERSION 2>/dev/null || echo "0.1.0")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/bonjoski/coppermind/pkg/version.Version=$(VERSION) \
	-X github.com/bonjoski/coppermind/pkg/version.Commit=$(COMMIT) \
	-X github.com/bonjoski/coppermind/pkg/version.BuildTime=$(DATE)

all: build test

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/coppermind ./cmd/coppermind

test:
	go test -v ./...

doctor: build
	./bin/coppermind doctor

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 bin/coppermind $(DESTDIR)$(BINDIR)/coppermind

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/coppermind

clean:
	rm -rf bin/
