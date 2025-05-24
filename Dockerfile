# Build stage
FROM golang:1.24.3-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o megadunder ./cmd/megadunder

# Final stage
FROM alpine:3.19

# Install necessary runtime dependencies for all tools
RUN apk add --no-cache \
    # Network tools
    curl \
    iputils \
    traceroute \
    busybox-extras \
    # DNS tools
    bind-tools \
    # SSL/TLS tools
    openssl \
    # Mail tools
    openssl-dev \
    cyrus-sasl \
    # Additional dependencies
    ca-certificates \
    tzdata \
    # Required for some network operations
    libidn2 \
    nghttp2-libs \
    libcrypto3 \
    libssl3

# Create necessary directories
RUN mkdir -p /app/certs /app/logs

# Create non-root user
RUN adduser -D -H -h /app appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/megadunder .
# Copy templates directory
COPY --from=builder /app/cmd/megadunder/templates ./templates
# Copy .env file if it exists (optional)
COPY --from=builder /app/.env* ./

# Expose the port the app runs on
EXPOSE 8080

# Set environment variables
ENV TZ=UTC \
    SSL_CERT_DIR=/etc/ssl/certs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Run the application
CMD ["./megadunder"] 