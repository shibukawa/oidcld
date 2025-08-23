# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.24 AS builder

# Set working directory
WORKDIR /app

# Build arguments for version information
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Copy go mod files and download dependencies with cache mount
RUN --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download -x

# Build the binary with bind mount for source and cache for build
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /usr/local/bin/oidcld .

# Final stage
FROM gcr.io/distroless/base-debian12:nonroot

# Copy the binary from builder
COPY --from=builder /usr/local/bin/oidcld /usr/local/bin/oidcld

# Use nonroot user (already set in base image)
# USER nonroot:nonroot

# Expose the default port
EXPOSE 18888

# Health check using the built-in health command
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/oidcld", "health"]

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/oidcld"]

# Default command
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="OpenID Connect Test Identity Provider"
LABEL org.opencontainers.image.description="A fake OpenID Connect Identity Provider for testing and development"
LABEL org.opencontainers.image.vendor="shibukawa"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/shibukawa/oidcld"
LABEL org.opencontainers.image.documentation="https://github.com/shibukawa/oidcld/blob/main/README.md"
