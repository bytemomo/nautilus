# Siren Makefile

.PHONY: all build clean install test run help deps fmt lint

# Variables
BINARY_NAME=siren
BUILD_DIR=build
CMD_DIR=cmd/siren
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"

# Default target
all: build

# Build the binary
build:
	@echo "Building Siren..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Install to $GOPATH/bin
install:
	@echo "Installing Siren..."
	$(GO) install $(GOFLAGS) $(LDFLAGS) ./$(CMD_DIR)
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(BINARY_NAME)
	@rm -rf captures/
	@echo "Clean complete"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "Dependencies updated"

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	@echo "Tests complete"

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "Format complete"

# Run linter
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed, install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin"; exit 1)
	golangci-lint run ./...
	@echo "Lint complete"

# Run with example configuration
run: build
	@echo "Running Siren with basic proxy config..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config scenarios/basic_proxy.yaml

# Run specific scenarios
run-packet-loss: build
	@echo "Running packet loss scenario..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config scenarios/packet_loss.yaml

run-latency: build
	@echo "Running latency scenario..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config scenarios/high_latency.yaml

run-corruption: build
	@echo "Running corruption scenario..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config scenarios/corruption.yaml

# Quick run with CLI args
run-cli: build
	@echo "Running Siren with CLI arguments..."
	./$(BUILD_DIR)/$(BINARY_NAME) -listen :8080 -target localhost:80 -proto tcp

# Create required directories
setup:
	@echo "Setting up directories..."
	@mkdir -p captures
	@mkdir -p scenarios
	@mkdir -p $(BUILD_DIR)
	@echo "Setup complete"

# Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	@echo "Build complete for all platforms"

# Display help
help:
	@echo "Siren - Man-in-the-Middle Testing Proxy"
	@echo ""
	@echo "Available targets:"
	@echo "  make build              - Build the Siren binary"
	@echo "  make install            - Install to GOPATH/bin"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make deps               - Download and tidy dependencies"
	@echo "  make test               - Run tests"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Run linter"
	@echo "  make run                - Run with basic proxy config"
	@echo "  make run-packet-loss    - Run packet loss scenario"
	@echo "  make run-latency        - Run latency scenario"
	@echo "  make run-corruption     - Run corruption scenario"
	@echo "  make run-cli            - Run with CLI arguments"
	@echo "  make setup              - Create required directories"
	@echo "  make build-all          - Build for multiple platforms"
	@echo "  make help               - Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make build"
	@echo "  ./build/siren -listen :8080 -target server.com:80 -proto tcp"
	@echo "  ./build/siren -config scenarios/packet_loss.yaml"
