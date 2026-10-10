.PHONY: build test lint vet fmt clean check

BINARY := hammerhead
VERSION ?= 0.1.0-dev
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X github.com/talarurus/hammerhead/internal/cli.Version=$(VERSION) -X github.com/talarurus/hammerhead/internal/cli.Commit=$(COMMIT)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/hammerhead

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	rm -f coverage.out coverage.html

coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run all quality checks
check: fmt vet test
