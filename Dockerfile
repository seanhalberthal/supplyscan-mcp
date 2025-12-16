FROM golang:1.25-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/seanhalberthal/supplyscan-mcp/internal/types.Version=${VERSION}" -o /supplyscan-mcp ./cmd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 scanner && \
    mkdir -p /cache /workspace && \
    chown scanner:scanner /cache /workspace
COPY --from=builder /supplyscan-mcp /usr/local/bin/
USER scanner
WORKDIR /workspace
ENTRYPOINT ["supplyscan-mcp"]