"""HTTP integration tests: endpoints, HMAC enforcement, limits.

Uses Starlette's TestClient (bundled with FastAPI) so the real ASGI app, its
lifespan and streaming are exercised without a network server. The HMAC
verifier is the real implementation; only Ghostscript is stubbed.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import main as main_module  # noqa: E402
from app.compressor import CompressionResult  # noqa: E402
from app.config import Settings  # noqa: E402
from app.security import KeyStore, NonceStore, Verifier  # noqa: E402
from tests.helpers import TOOL_SLUG, signed_headers, write_key_file  # noqa: E402

MINIMAL_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def _make_app(monkeypatch, *, limit=1000, concurrency=3, max_bytes=25 * 1024 * 1024):
    key_dir = tempfile.mkdtemp(prefix="pdfc-keys-")
    write_key_file(key_dir)
    settings = Settings(
        hmac_keys_dir=key_dir,
        tool_slug=TOOL_SLUG,
        nonce_db_path=os.path.join(tempfile.mkdtemp(prefix="pdfc-db-"), "n.db"),
        max_upload_bytes=max_bytes,
        rate_limit_per_minute=limit,
        max_concurrency=concurrency,
    )
    verifier = Verifier(
        key_store=KeyStore(key_dir),
        nonce_store=NonceStore(settings.nonce_db_path),
        tool_slug=TOOL_SLUG,
    )

    def fake_compress(content, level, timeout_seconds, ghostscript_bin="gs"):
        return CompressionResult(
            content=b"%PDF-1.4 compressed",
            original_size=len(content),
            compressed_size=18,
            kept_original=False,
        )

    monkeypatch.setattr(main_module, "compress_pdf", fake_compress)
    return main_module.create_app(settings=settings, verifier=verifier)


@pytest.fixture()
def client(monkeypatch):
    app = _make_app(monkeypatch)
    with TestClient(app, client=("1.2.3.4", 5000)) as test_client:
        yield test_client


BOUNDARY = "pdfcTestBoundary7d01"


def _multipart_body(pdf: bytes, level: str = "medium") -> bytes:
    return (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="level"\r\n\r\n'
        f"{level}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="file"; filename="doc.pdf"\r\n'
        "Content-Type: application/pdf\r\n\r\n"
    ).encode("utf-8") + pdf + f"\r\n--{BOUNDARY}--\r\n".encode("utf-8")


def _multipart_headers(pdf: bytes, *, level: str = "medium", sign_body: bytes | None = None,
                       nonce: str = "mp-1", bad_signature: bool = False):
    """Sign the exact multipart body Core would hash, then return headers."""
    raw = _multipart_body(pdf, level)
    headers = signed_headers(
        "POST", "/compress", sign_body if sign_body is not None else raw,
        nonce=nonce,
    )
    headers["Content-Type"] = f"multipart/form-data; boundary={BOUNDARY}"
    if bad_signature:
        headers["X-Signature"] = "00" * 32
    return raw, headers


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_index_renders_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PDF Compressor" in response.text


def test_compress_requires_signature(client):
    raw = _multipart_body(MINIMAL_PDF)
    response = client.post(
        "/compress", content=raw,
        headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
    )
    assert response.status_code == 401


def test_compress_rejects_bad_signature(client):
    raw, headers = _multipart_headers(MINIMAL_PDF, nonce="http-bad-1",
                                      bad_signature=True)
    response = client.post("/compress", content=raw, headers=headers)
    assert response.status_code == 401


def test_compress_success_with_valid_signature(client):
    raw, headers = _multipart_headers(MINIMAL_PDF, nonce="http-ok-1")
    response = client.post("/compress", content=raw, headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["X-Original-Size"] == str(len(MINIMAL_PDF))
    assert response.headers["X-Compressed-Size"] == "18"
    assert response.content.startswith(b"%PDF-")


def test_compress_rejects_non_pdf(client):
    body = b"PK\x03\x04not a pdf"
    raw, headers = _multipart_headers(body, nonce="http-nonpdf")
    response = client.post("/compress", content=raw, headers=headers)
    assert response.status_code == 400
    assert response.json()["success"] is False


def test_compress_rejects_oversize(monkeypatch):
    app = _make_app(monkeypatch, max_bytes=64)
    with TestClient(app, client=("1.2.3.4", 5000)) as test_client:
        big = b"%PDF-1.4" + b"a" * 1024
        raw, headers = _multipart_headers(big, nonce="http-big")
        response = test_client.post("/compress", content=raw, headers=headers)
        assert response.status_code == 413


def test_compress_rejects_bad_level(client):
    raw, headers = _multipart_headers(MINIMAL_PDF, level="extreme",
                                      nonce="http-badlvl")
    response = client.post("/compress", content=raw, headers=headers)
    assert response.status_code == 400


def test_compress_rejects_tampered_body(client):
    """Signature covers the multipart envelope: swapping the payload must fail."""
    signed_raw = _multipart_body(MINIMAL_PDF, "medium")
    _, headers = _multipart_headers(MINIMAL_PDF, nonce="http-tamper")
    tampered = _multipart_body(b"%PDF-1.4 tampered payload", "medium")
    assert tampered != signed_raw
    response = client.post("/compress", content=tampered, headers=headers)
    assert response.status_code == 401


def test_rate_limit_returns_429(monkeypatch):
    app = _make_app(monkeypatch, limit=2)
    with TestClient(app, client=("9.9.9.9", 5000)) as test_client:
        codes = []
        for i in range(3):
            raw, headers = _multipart_headers(MINIMAL_PDF, level="low",
                                              nonce=f"rl-{i}")
            codes.append(test_client.post(
                "/compress", content=raw, headers=headers).status_code)
        assert codes == [200, 200, 429]


def test_concurrency_guard_returns_503(monkeypatch):
    app = _make_app(monkeypatch, concurrency=1)
    guarded = app.state.guard
    assert guarded.try_acquire() is True
    try:
        with TestClient(app, client=("8.8.8.8", 5000)) as test_client:
            raw, headers = _multipart_headers(MINIMAL_PDF, level="low",
                                              nonce="cc-1")
            response = test_client.post("/compress", content=raw, headers=headers)
            assert response.status_code == 503
    finally:
        guarded.release()
