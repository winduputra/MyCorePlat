# Tools BPBJ — Core production image.
#
# Multi-stage build: the builder compiles a static Go binary, the runtime stage
# ships only that binary on a distroless base (no shell, no package manager, no
# compiler). Runs as a non-root user and exposes an HTTP port for the internal
# Docker network only.
#
# Build (from the repository root):
#   docker build -f deploy/core/Dockerfile -t tools-bpbj/core:dev .
#
# The runtime image contains NO secrets. Everything sensitive is injected at
# run time via environment variables or mounted secret files (see
# deploy/core/docker-compose.yml).

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM golang:1.27-bookworm AS builder

WORKDIR /src

# Cache dependencies separately from the source code.
COPY go.mod go.sum ./
RUN go mod download

# Build the binary.
COPY . .
ENV CGO_ENABLED=0
ENV GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/core ./cmd/core

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# Distroless static already includes CA certificates and runs as uid 65532
# (nonroot) by default. tzdata is intentionally omitted: the app stores all
# timestamps in UTC explicitly and does not rely on the system timezone.

WORKDIR /app
COPY --from=builder /out/core /app/core

# HTTP port on the internal network only. Not published to the host.
EXPOSE 8080

# Exec-form entrypoint so the process is PID 1 and receives SIGTERM/SIGINT,
# which the application handles for graceful shutdown.
ENTRYPOINT ["/app/core"]
