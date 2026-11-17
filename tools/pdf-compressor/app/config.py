"""PDF Compressor tool configuration.

All settings come from environment variables so the container can be
configured at deploy time without rebuilding the image. Defaults are safe:
the tool refuses to start without a provisioned signing key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Upload ceiling mirrors the Core gateway default (25 MiB). Keeping the tool
# limit equal to the gateway limit means a request that reaches the tool has
# already passed the same size gate.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

# Hard processing timeout. Kept below the gateway response-header timeout
# (60s) so the tool always answers before the gateway gives up on it.
PROCESSING_TIMEOUT_SECONDS = 45.0

# Minimal PDF signature. A real PDF starts with "%PDF-"; anything else is
# rejected before Ghostscript is ever invoked.
PDF_MAGIC = b"%PDF-"

# Accepted compression levels.
COMPRESSION_LEVELS = ("low", "medium", "high")

# Ghostscript presets per level. Higher resolution downsampling and a more
# aggressive image quality produce smaller files at some visual cost.
GHOSTSCRIPT_PRESETS: dict[str, list[str]] = {
    "low": ["-dPDFSETTINGS=/prepress"],
    "medium": ["-dPDFSETTINGS=/ebook"],
    "high": ["-dPDFSETTINGS=/screen"],
}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return float(raw)


@dataclass(frozen=True)
class Settings:
    """Runtime configuration resolved once at startup."""

    # Signing keys directory. Each tool reads its own <slug>.json file, the
    # same format Core uses (keyId, secret base64, status, notAfter).
    hmac_keys_dir: str = ""
    tool_slug: str = "pdf-compressor"
    hmac_skew_seconds: int = 60

    # Replay-protection store. Uses SQLite so the check-and-store is atomic
    # (a UNIQUE constraint) and survives process restarts.
    nonce_db_path: str = "/tmp/nonces.db"
    nonce_ttl_seconds: int = 300

    max_upload_bytes: int = MAX_UPLOAD_BYTES
    processing_timeout_seconds: float = PROCESSING_TIMEOUT_SECONDS

    # Per-IP rate limiting and global concurrency cap.
    rate_limit_per_minute: int = 20
    max_concurrency: int = 3

    # Ghostscript binary. Configurable for tests that inject a fake.
    ghostscript_bin: str = "gs"

    levels: tuple[str, ...] = field(default_factory=lambda: COMPRESSION_LEVELS)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            hmac_keys_dir=os.environ.get("TOOL_HMAC_KEYS_DIR", "").strip(),
            tool_slug=os.environ.get("TOOL_SLUG", "pdf-compressor").strip(),
            hmac_skew_seconds=_env_int("HMAC_SKEW_SECONDS", 60),
            nonce_db_path=os.environ.get("NONCE_DB_PATH", "/tmp/nonces.db").strip(),
            nonce_ttl_seconds=_env_int("NONCE_TTL_SECONDS", 300),
            max_upload_bytes=_env_int("MAX_UPLOAD_BYTES", MAX_UPLOAD_BYTES),
            processing_timeout_seconds=_env_float(
                "PROCESSING_TIMEOUT_SECONDS", PROCESSING_TIMEOUT_SECONDS
            ),
            rate_limit_per_minute=_env_int("RATE_LIMIT_PER_MINUTE", 20),
            max_concurrency=_env_int("MAX_CONCURRENCY", 3),
            ghostscript_bin=os.environ.get("GHOSTSCRIPT_BIN", "gs").strip(),
        )
