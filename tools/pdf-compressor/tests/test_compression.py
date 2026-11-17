"""Unit tests for validation and compression (Ghostscript is injected)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.compressor import (  # noqa: E402
    CompressionError,
    compress_pdf,
    gs_arguments,
)
from app.validation import (  # noqa: E402
    ValidationError,
    validate_level,
    validate_pdf,
    validate_size,
)

MINIMAL_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


class FakeRunner:
    """Stands in for subprocess.run, writing a controlled output file."""

    def __init__(self, output_bytes: bytes, *, returncode: int = 0,
                 raise_timeout: bool = False, raise_missing: bool = False):
        self.output_bytes = output_bytes
        self.returncode = returncode
        self.raise_timeout = raise_timeout
        self.raise_missing = raise_missing
        self.commands: list[list[str]] = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if self.raise_missing:
            raise FileNotFoundError("gs")
        if self.raise_timeout:
            raise subprocess.TimeoutExpired(cmd="gs", timeout=1)
        output_path = next(
            (arg.split("=", 1)[1] for arg in command if arg.startswith("-sOutputFile=")),
            None,
        )
        if output_path:
            with open(output_path, "wb") as handle:
                handle.write(self.output_bytes)
        if self.returncode != 0:
            raise subprocess.CalledProcessError(self.returncode, "gs")
        return subprocess.CompletedProcess(command, 0, b"", b"")


# --- validation -----------------------------------------------------------


def test_validate_pdf_accepts_real_signature():
    validate_pdf(MINIMAL_PDF)  # must not raise


def test_validate_pdf_rejects_non_pdf():
    with pytest.raises(ValidationError):
        validate_pdf(b"PK\x03\x04 this is a zip")


def test_validate_pdf_rejects_empty():
    with pytest.raises(ValidationError):
        validate_pdf(b"")


def test_validate_size_accepts_within_limit():
    validate_size(1000, 25 * 1024 * 1024)


def test_validate_size_rejects_over_limit():
    with pytest.raises(ValidationError) as exc:
        validate_size(26 * 1024 * 1024, 25 * 1024 * 1024)
    assert exc.value.status_code == 413


@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_validate_level_accepts_known(level):
    assert validate_level(level) == level


def test_validate_level_normalizes_case():
    assert validate_level("MEDIUM") == "medium"


def test_validate_level_rejects_unknown():
    with pytest.raises(ValidationError):
        validate_level("extreme")


# --- ghostscript arguments ------------------------------------------------


def test_gs_arguments_always_include_dsafer():
    for level in ("low", "medium", "high"):
        assert "-dSAFER" in gs_arguments(level)


def test_gs_arguments_use_level_preset():
    assert "-dPDFSETTINGS=/screen" in gs_arguments("high")
    assert "-dPDFSETTINGS=/prepress" in gs_arguments("low")


# --- compression ----------------------------------------------------------


def test_compress_returns_smaller_output():
    smaller = b"%PDF-1.4 compressed"
    runner = FakeRunner(smaller)
    result = compress_pdf(MINIMAL_PDF, "medium", 45, runner=runner)
    assert result.content == smaller
    assert result.compressed_size == len(smaller)
    assert result.original_size == len(MINIMAL_PDF)
    assert result.kept_original is False


def test_compress_keeps_original_when_larger():
    bigger = b"%PDF-1.4" + b"x" * 10_000
    runner = FakeRunner(bigger)
    result = compress_pdf(MINIMAL_PDF, "low", 45, runner=runner)
    assert result.content == MINIMAL_PDF
    assert result.kept_original is True
    assert result.compressed_size == len(MINIMAL_PDF)


def test_compress_fails_when_ghostscript_missing():
    with pytest.raises(CompressionError):
        compress_pdf(MINIMAL_PDF, "medium", 45, runner=FakeRunner(b"", raise_missing=True))


def test_compress_fails_on_timeout():
    with pytest.raises(CompressionError) as exc:
        compress_pdf(MINIMAL_PDF, "medium", 1, runner=FakeRunner(b"", raise_timeout=True))
    assert "waktu" in str(exc.value).lower()


def test_compress_fails_on_nonzero_exit():
    with pytest.raises(CompressionError):
        compress_pdf(MINIMAL_PDF, "medium", 45, runner=FakeRunner(b"", returncode=1))


def test_compress_temp_files_removed_on_success():
    runner = FakeRunner(b"%PDF-1.4 small")
    before = set(_temp_entries())
    compress_pdf(MINIMAL_PDF, "medium", 45, runner=runner)
    after = set(_temp_entries())
    leaked = {name for name in after - before if name.startswith("pdfc-")}
    assert leaked == set()


def test_compress_temp_files_removed_on_failure():
    before = set(_temp_entries())
    with pytest.raises(CompressionError):
        compress_pdf(MINIMAL_PDF, "medium", 45, runner=FakeRunner(b"", returncode=1))
    after = set(_temp_entries())
    leaked = {name for name in after - before if name.startswith("pdfc-")}
    assert leaked == set()


def test_compress_output_path_is_inside_temp_dir():
    runner = FakeRunner(b"%PDF-1.4 small")
    compress_pdf(MINIMAL_PDF, "high", 45, runner=runner)
    command = runner.commands[0]
    output = next(arg for arg in command if arg.startswith("-sOutputFile="))
    assert "pdfc-" in output


def _temp_entries() -> list[str]:
    return os.listdir(tempfile.gettempdir())
