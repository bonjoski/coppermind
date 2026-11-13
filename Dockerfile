# Multi-stage build for Coppermind Distributed Appliance
FROM golang:1.27-alpine AS builder

WORKDIR /build
RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.Version=0.1.0-cluster" \
    -o /build/coppermind ./cmd/coppermind

# Minimal scratch runtime
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/coppermind /coppermind

USER 65532:65532
VOLUME ["/data"]
ENV COPPERMIND_DATA_DIR=/data

EXPOSE 8765
ENTRYPOINT ["/coppermind"]
CMD ["daemon", "--listen", "0.0.0.0:8765"]
