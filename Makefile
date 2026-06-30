.PHONY: build build-ui run test clean dev docker-build docker-run setup certs

# Application name
APP_NAME=adel
BUILD_DIR=bin
WEB_DIR=web

# Build the React frontend and copy assets into static/dist/
build-ui:
	cd $(WEB_DIR) && npm ci && npm run build
	rm -rf static/dist
	cp -r $(WEB_DIR)/dist static/dist

# Build the Go binary (embeds whatever is in static/dist/)
build:
	go build -o $(BUILD_DIR)/$(APP_NAME) .

# Full build: frontend then backend
build-all: build-ui build

# Run the application (requires static/dist to be populated)
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
	rm -rf static/dist
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
	@echo "  build-ui      - Build React frontend into static/dist/"
	@echo "  build         - Build the Go binary (embeds static/dist/)"
	@echo "  build-all     - Build frontend then backend (full release build)"
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
