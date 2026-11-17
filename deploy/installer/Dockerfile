# Tool Installer — multi-stage build.
#
# Build from the repository root:
#   docker build -f deploy/installer/Dockerfile -t tools-bpbj/installer:dev .
#
# DOCKER SOCKET ACCESS (important):
# The installer runs as a NON-ROOT user but must read /var/run/docker.sock.
# On the host that socket is normally owned by root:docker with mode 0660, so
# the runtime user must belong to a group whose GID matches the host `docker`
# group. Pass it at build time:
#
#   docker build --build-arg DOCKER_GID=$(stat -c '%g' /var/run/docker.sock) \
#     -f deploy/installer/Dockerfile -t tools-bpbj/installer:dev .
#
# docker-compose.yml supplies the same value via the DOCKER_GID build arg.
# The default (999) matches a typical Debian/Ubuntu docker group; override it
# if the host differs. Never fall back to running the installer as root.
FROM golang:1.27-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ENV GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/installer ./cmd/installer

# Runtime: Debian slim provides a shell and the `docker` CLI is NOT needed —
# the installer talks to the Engine API over the mounted socket directly.
FROM debian:bookworm-slim AS runtime

ARG DOCKER_GID=999

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 installer \
    && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin installer \
    && if getent group "${DOCKER_GID}" >/dev/null; then \
           usermod -aG "$(getent group ${DOCKER_GID} | cut -d: -f1)" installer; \
       else \
           groupadd -g "${DOCKER_GID}" dockerhost && usermod -aG dockerhost installer; \
       fi

WORKDIR /app
COPY --from=builder /out/installer /app/installer

# The work dir holds extracted packages and build contexts; it is wiped on
# restart. The HMAC key directory must be a mounted volume so it survives.
ENV INSTALLER_WORK_DIR=/tmp/installer
ENV TOOL_HMAC_KEYS_DIR=/run/secrets/tool-hmac
ENV INSTALLER_ADDR=:8090

EXPOSE 8090

USER 10002:10002

# Health probe uses the binary itself; no shell/curl needed.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD ["/app/installer", "-healthcheck"]

ENTRYPOINT ["/app/installer"]
