# PDF Compressor — MyCorePlat tool image.
#
# Multi-stage build:
#   stage 1 (builder) installs Python dependencies into a virtualenv.
#   stage 2 (runtime) carries only the finished virtualenv, the application,
#            and Ghostscript, and runs as a non-root user.
#
# Build (from the repository root so the .dockerignore applies):
#   docker build -f tools/pdf-compressor/Dockerfile -t tools-bpbj/pdf-compressor:dev tools/pdf-compressor
#
# The runtime image contains NO secrets. The per-tool HMAC key file is mounted
# at runtime (see docker-compose.yml) and is never baked into the image.

# ---- Stage 1: build the virtualenv --------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build-time compiler for any wheel that needs it (kept in the builder only).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install runtime dependencies into an isolated virtualenv.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

# ---- Stage 2: runtime ----------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# Ghostscript is the compression engine. Install only what is needed and drop
# the package lists in the same layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ghostscript \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. UID/GID 10001 is unprivileged and not used by the base image.
RUN groupadd --gid 10001 pdfc \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin pdfc

# Copy the prepared virtualenv and the application code.
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY app/ ./app/

# The container is designed to run with a read-only root filesystem; the only
# writable paths (temp work dir for Ghostscript and the SQLite nonce store)
# are provided as a tmpfs at runtime.
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TOOL_SLUG=pdf-compressor \
    NONCE_DB_PATH=/tmp/nonces.db \
    GHOSTSCRIPT_BIN=gs

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

# Exec form so the process receives SIGTERM/SIGINT for a clean shutdown.
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
