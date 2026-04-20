# syntax=docker/dockerfile:1

# Build admin console assets
FROM node:25-trixie AS admin-builder

WORKDIR /app/web/admin

COPY web/admin/package.json web/admin/package-lock.json ./

RUN npm ci

COPY web/admin/ ./

RUN npm run build

# Build stage
FROM golang:1.26-trixie AS builder

WORKDIR /app

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download -x

COPY . .
COPY --from=admin-builder /app/web/admin/dist /tmp/admin-dist

RUN mkdir -p internal/server/adminassets/generated && \
    find internal/server/adminassets/generated -mindepth 1 ! -name placeholder.txt -exec rm -rf {} + && \
    cp -R /tmp/admin-dist/. internal/server/adminassets/generated/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /usr/local/bin/oidcld .

RUN mkdir -p /tmp/runtime-app/tls

# Final stage
FROM gcr.io/distroless/base-debian13:nonroot

WORKDIR /app

# Seed the named volume mount point with a nonroot-owned directory so the CA can persist files.
COPY --from=builder --chown=nonroot:nonroot /tmp/runtime-app /app

# Copy the binary from builder
COPY --from=builder /usr/local/bin/oidcld /usr/local/bin/oidcld

# Use nonroot user (already set in base image)
# USER nonroot:nonroot

# Expose default runtime ports
EXPOSE 18888 18443

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
