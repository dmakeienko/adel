.PHONY: build run test clean dev docker-build docker-run setup certs

# Application name
APP_NAME=adel
BUILD_DIR=bin

# Build the application
build:
	go build -o $(BUILD_DIR)/$(APP_NAME) .

# Run the application
run: build
	./$(BUILD_DIR)/$(APP_NAME)

# Run directly without building
run-dev:
	go run .

# Run setup script
setup:
	./scripts/setup.sh

# Generate self-signed certificates for development
certs:
	@mkdir -p certs
	@openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
	@echo "Self-signed certificates generated in certs/"

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)/
	rm -f coverage.out coverage.html

# Run in development mode with hot reload (requires air)
dev:
	air

# Install development dependencies
install-dev:
	go install github.com/cosmtrek/air@latest

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Tidy dependencies
tidy:
	go mod tidy

# Update dependencies
update:
	go get -u ./...
	go mod tidy

# Build Docker image
docker-build:
	docker build -t $(APP_NAME):latest .

# Run Docker container
docker-run:
	docker run -p 8080:8080 --env-file .env $(APP_NAME):latest

# Show help
help:
	@echo "Available targets:"
	@echo "  build         - Build the application"
	@echo "  run           - Build and run the application"
	@echo "  run-dev       - Run without building (go run)"
	@echo "  setup         - Run setup script"
	@echo "  certs         - Generate self-signed certificates"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean         - Clean build artifacts"
	@echo "  dev           - Run with hot reload (requires air)"
	@echo "  install-dev   - Install development dependencies"
	@echo "  fmt           - Format code"
	@echo "  vet           - Vet code"
	@echo "  lint          - Run linter"
	@echo "  tidy          - Tidy dependencies"
	@echo "  update        - Update dependencies"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
