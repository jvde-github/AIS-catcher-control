COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.buildVersion=$(COMMIT)"

.PHONY: build run

build:
	go build $(LDFLAGS) -o AIS-catcher-control .

run:
	go run $(LDFLAGS) .
