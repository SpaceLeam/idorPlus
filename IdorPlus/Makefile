.PHONY: build clean install test lint fmt vet docker run help

APP_NAME=idorplus
VERSION=2.0.0
BUILD_TIME=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Default target
all: build

# Build the binary
build:
	@echo "Building $(APP_NAME) v$(VERSION)..."
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(APP_NAME) main.go
	@echo "Build complete: bin/$(APP_NAME)"

# Install to GOPATH/bin
install:
	go install $(LDFLAGS) .

# Run tests
test:
	@echo "Running tests..."
	go test ./tests/... -v -cover

# Run all tests with race detection
test-race:
	go test ./tests/... -v -race

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Lint (requires golangci-lint)
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f *.json
	rm -f *.log

# Build for multiple platforms
cross-build:
	@echo "Building for multiple platforms..."
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(APP_NAME)-linux-amd64 main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(APP_NAME)-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(APP_NAME)-darwin-arm64 main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(APP_NAME)-windows-amd64.exe main.go
	@echo "Cross-build complete!"

# Docker build
docker:
	docker build -t $(APP_NAME):$(VERSION) .

# Run the application
run:
	go run main.go

# Run with example
run-example:
	go run main.go scan -u "http://localhost:8080/api/users/{ID}" -t 5 -n 20

# Download dependencies
deps:
	go mod download
	go mod tidy

# Show help
help:
	@echo "IdorPlus Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build       - Build the binary"
	@echo "  make install     - Install to GOPATH/bin"
	@echo "  make test        - Run tests"
	@echo "  make test-race   - Run tests with race detection"
	@echo "  make fmt         - Format code"
	@echo "  make vet         - Vet code"
	@echo "  make lint        - Lint code (requires golangci-lint)"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make cross-build - Build for multiple platforms"
	@echo "  make docker      - Build Docker image"
	@echo "  make deps        - Download dependencies"
	@echo "  make run         - Run the application"
	@echo "  make help        - Show this help"
