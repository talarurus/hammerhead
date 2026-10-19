.PHONY: build test vet check clean
BINARY := dist/hammerhead-core
# Native platform only. Release qualification does not follow from cross-compilation.
build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o $(BINARY) ./cmd/hammerhead-core
test:
	go test -race -count=1 ./...
vet:
	go vet ./...
check: vet test
clean:
	rm -f $(BINARY)
