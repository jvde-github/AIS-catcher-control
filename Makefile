VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.buildVersion=$(VERSION) -X main.buildCommit=$(COMMIT)"

.PHONY: build run

build:
	go build $(LDFLAGS) -o AIS-catcher-control .

run:
	go run $(LDFLAGS) .
