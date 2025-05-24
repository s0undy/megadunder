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

# Install necessary runtime dependencies for network tools
RUN apk add --no-cache \
    curl \
    iputils \
    bind-tools \
    traceroute \
    busybox-extras

# Create non-root user
RUN adduser -D -H -h /app appuser
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

# Run the application
CMD ["./megadunder"] 