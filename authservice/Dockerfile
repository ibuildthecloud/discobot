# Stage 0: Download shared Go module dependencies for root-module binaries
FROM golang:1.26 AS root-go-deps

WORKDIR /build

# Copy module files first for better caching
# modelsdev/go.mod is needed by the replace directive in the root go.mod
COPY modelsdev/go.mod ./modelsdev/
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Stage 1: Build the authservice binary from source
FROM root-go-deps AS authservice-builder

ARG TARGETOS
ARG TARGETARCH

# Copy authservice source and local module replacements
COPY authservice/ ./authservice/
COPY modelsdev/ ./modelsdev/

# Build the authservice binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /discobot-authservice \
    ./authservice/cmd/authservice

# Stage 2: Minimal Ubuntu runtime for authservice
FROM ubuntu:24.04 AS authservice

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 -s /usr/sbin/nologin discobot \
    && mkdir -p /data \
    && chown -R discobot:discobot /data

COPY --from=authservice-builder /discobot-authservice /usr/local/bin/discobot-authservice

ENV XDG_DATA_HOME=/data
ENV PORT=3010

# Persist the default SQLite database and other authservice state on a Docker volume.
VOLUME ["/data"]

WORKDIR /data
USER discobot

EXPOSE 3010

ENTRYPOINT ["/usr/local/bin/discobot-authservice"]
