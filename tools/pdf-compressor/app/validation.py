"""Upload validation: signature, size and compression level."""

from __future__ import annotations

from .config import COMPRESSION_LEVELS, PDF_MAGIC


class ValidationError(Exception):
    """A request the tool rejects with a user-facing message."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def validate_pdf(content: bytes) -> None:
    """Reject anything that is not a PDF, before Ghostscript runs.

    The magic bytes are checked rather than the declared Content-Type: a
    browser can claim any type it likes, but it cannot fake the file header.
    """
    if not content:
        raise ValidationError("File kosong. Silakan unggah berkas PDF.", 400)
    if not content.startswith(PDF_MAGIC):
        raise ValidationError(
            "Berkas tidak dikenali sebagai PDF yang valid.", 400
        )


def validate_size(size: int, max_bytes: int) -> None:
    if size > max_bytes:
        megabytes = max_bytes // (1024 * 1024)
        raise ValidationError(
            f"Ukuran berkas melebihi batas {megabytes} MiB.", 413
        )


def validate_level(level: str) -> str:
    normalized = (level or "").strip().lower()
    if normalized not in COMPRESSION_LEVELS:
        raise ValidationError(
            "Tingkat kompresi tidak valid. Pilih low, medium, atau high.", 400
        )
    return normalized
