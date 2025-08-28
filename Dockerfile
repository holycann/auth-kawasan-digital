# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    git \
    curl \
    build-base

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux APP_ENV=production go build -o /bin/app \
    -ldflags="-X 'main.BuildVersion=$(git describe --tags --always)' \
              -X 'main.BuildTime=$(date)' \
              -X 'main.BuildCommit=$(git rev-parse HEAD)'" \
    ./cmd/main.go

# Stage 2: Create minimal runtime image
FROM alpine:latest

# Install system dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    bash

# Set working directory
WORKDIR /app

# Create logs directory
RUN mkdir -p /app/logs

# Copy built binary from builder stage
COPY --from=builder /bin/app /app/app

# Set timezone
ENV TZ=UTC

# Expose application port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/app"]

# Default command (can be overridden)
CMD ["serve"] 