#  Stage 1: Build
# Use the official Go image to compile the binary
FROM golang:1.22-alpine AS builder

# Install ca-certificates (needed for HTTPS calls if any) and timezone data.
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy dependency files first and download modules.
# Docker caches this layer unless go.mod or go.sum changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy all source files and build the binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o burrow \
    ./cmd/burrow

# Stage 2: Runtime
# Distroless has no shell, no package manager, and minimal attack surface.
# The binary is the only thing that runs in this image.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# Copy timezone data and certs from builder.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary.
COPY --from=builder /app/burrow /burrow

# Create the directory for the SQLite database.
# The 'nonroot' distroless image runs as UID 65532.
USER nonroot:nonroot

# Expose the default port.
EXPOSE 8080

# Health check via /health endpoint
# Distroless has no shell or curl, so we rely on docker-compose healthcheck
# or an orchestrator probe. Remove this if using Kubernetes liveness probes.
# Note: distroless images cannot run shell-based health checks.

ENTRYPOINT ["/burrow"]
