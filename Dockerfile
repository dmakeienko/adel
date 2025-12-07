# Build stage
FROM golang:1.25-alpine3.23 AS builder

# Set working directory
WORKDIR /app

# Install git (needed for some Go modules)
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:3.23

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create a non-root user
RUN addgroup -g 1001 -S adel && \
    adduser -S adel -u 1001

# Set working directory
WORKDIR /home/adel

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Change ownership of the binary
RUN chown adel:adel main

# Switch to non-root user
USER adel

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"]
