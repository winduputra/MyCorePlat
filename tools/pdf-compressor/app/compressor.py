"""Ghostscript-backed PDF compression.

Ghostscript is invoked through a subprocess in an isolated temporary
directory. All temporary files are removed before the function returns,
whether it succeeded or not.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from .config import GHOSTSCRIPT_PRESETS


class CompressionError(Exception):
    """Compression failed in a way the user should be told about."""


@dataclass(frozen=True)
class CompressionResult:
    """Outcome of one compression attempt.

    ``content`` is either the compressed bytes or, when compression made the
    file larger, the original bytes unchanged (``kept_original`` is then true).
    """

    content: bytes
    original_size: int
    compressed_size: int
    kept_original: bool


def gs_arguments(level: str) -> list[str]:
    """The Ghostscript flags for a level, always including -dSAFER."""
    preset = GHOSTSCRIPT_PRESETS[level]
    return [
        "-sDEVICE=pdfwrite",
        "-dSAFER",
        "-dNOPAUSE",
        "-dBATCH",
        "-dQUIET",
        "-dCompatibilityLevel=1.4",
        *preset,
    ]


def compress_pdf(
    content: bytes,
    level: str,
    timeout_seconds: float,
    ghostscript_bin: str = "gs",
    runner=subprocess.run,
) -> CompressionResult:
    """Compress ``content`` with Ghostscript.

    Raises CompressionError when Ghostscript is missing, times out, or fails.
    ``runner`` is injectable so tests do not need a Ghostscript install.
    """
    original_size = len(content)
    workdir = tempfile.mkdtemp(prefix="pdfc-")
    try:
        source = os.path.join(workdir, "input.pdf")
        target = os.path.join(workdir, "output.pdf")
        with open(source, "wb") as handle:
            handle.write(content)

        command = [
            ghostscript_bin,
            *gs_arguments(level),
            f"-sOutputFile={target}",
            source,
        ]
        try:
            runner(
                command,
                check=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise CompressionError("Mesin kompresi tidak tersedia.") from exc
        except subprocess.TimeoutExpired as exc:
            raise CompressionError(
                "Waktu pemrosesan habis. Coba berkas yang lebih kecil."
            ) from exc
        except subprocess.CalledProcessError as exc:
            # stderr is intentionally not surfaced: it may contain file paths.
            raise CompressionError("Berkas gagal dikompres.") from exc

        if not os.path.exists(target) or os.path.getsize(target) == 0:
            raise CompressionError("Hasil kompresi tidak valid.")
        with open(target, "rb") as handle:
            compressed = handle.read()

        if len(compressed) >= original_size:
            return CompressionResult(
                content=content,
                original_size=original_size,
                compressed_size=original_size,
                kept_original=True,
            )
        return CompressionResult(
            content=compressed,
            original_size=original_size,
            compressed_size=len(compressed),
            kept_original=False,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
