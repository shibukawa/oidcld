# syntax=docker/dockerfile:1

FROM golang:1.24 AS builder

WORKDIR /app

# Cache Go modules
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download

# Build the application
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/device-flow-cli .

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder /app/device-flow-cli /device-flow-cli

ENTRYPOINT ["/device-flow-cli"]
