"""Unit tests for HMAC verification, nonce replay protection and key loading."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.security import (  # noqa: E402
    BODY_HASH_STREAMED,
    HEADER_BODY_DIGEST,
    HEADER_BODY_SIGNATURE,
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    KeyStore,
    NonceStore,
    SignatureError,
    Verifier,
    body_digest_signature,
    body_hash,
    canonical_string,
)
from tests.helpers import (  # noqa: E402
    ACTIVE_KEY_ID,
    PREVIOUS_KEY_ID,
    REVOKED_KEY_ID,
    TEST_SECRET,
    TOOL_SLUG,
    sign,
    signed_headers,
    write_key_file,
)


@pytest.fixture()
def key_dir():
    with tempfile.TemporaryDirectory() as directory:
        write_key_file(directory)
        yield directory


@pytest.fixture()
def nonce_store(tmp_path):
    return NonceStore(str(tmp_path / "nonces.db"))


@pytest.fixture()
def verifier(key_dir, nonce_store):
    return Verifier(
        key_store=KeyStore(key_dir),
        nonce_store=nonce_store,
        tool_slug=TOOL_SLUG,
        skew_seconds=60,
        nonce_ttl_seconds=300,
    )


def test_valid_signature_is_accepted(verifier):
    body = b"%PDF-1.4 hello"
    headers = signed_headers("POST", "/compress", body, nonce="n-valid-1")
    verifier.verify("POST", "/compress", "", headers, body)  # must not raise


def test_missing_signature_headers_rejected(verifier):
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", {}, b"%PDF-1.4")


def test_wrong_signature_rejected(verifier):
    body = b"%PDF-1.4 hello"
    headers = signed_headers("POST", "/compress", body, nonce="n-wrong")
    headers[HEADER_SIGNATURE] = "00" * 32
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_modified_body_rejected(verifier):
    body = b"%PDF-1.4 hello"
    headers = signed_headers("POST", "/compress", body, nonce="n-modbody")
    tampered = b"%PDF-1.4 HELLO"
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, tampered)


def test_modified_path_rejected(verifier):
    body = b"%PDF-1.4"
    headers = signed_headers("POST", "/compress", body, nonce="n-modpath")
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/other", "", headers, body)


def test_expired_timestamp_rejected(verifier):
    body = b"%PDF-1.4"
    old = int(time.time()) - 3600
    headers = signed_headers("POST", "/compress", body, timestamp=old, nonce="n-old")
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_future_timestamp_rejected(verifier):
    body = b"%PDF-1.4"
    future = int(time.time()) + 3600
    headers = signed_headers("POST", "/compress", body, timestamp=future, nonce="n-fut")
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_unknown_key_rejected(verifier):
    body = b"%PDF-1.4"
    headers = signed_headers("POST", "/compress", body, key_id="k-nope", nonce="n-unk")
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_revoked_key_rejected(verifier):
    body = b"%PDF-1.4"
    headers = signed_headers(
        "POST", "/compress", body,
        secret=b"revoked-secret-key-32-bytes!!!",
        key_id=REVOKED_KEY_ID, nonce="n-rev",
    )
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_previous_key_accepted_during_rotation(verifier):
    body = b"%PDF-1.4"
    headers = signed_headers(
        "POST", "/compress", body,
        secret=b"previous-secret-key-32-bytes!!",
        key_id=PREVIOUS_KEY_ID, nonce="n-prev",
    )
    verifier.verify("POST", "/compress", "", headers, body)  # must not raise


def test_duplicate_nonce_rejected(verifier):
    body = b"%PDF-1.4"
    headers = signed_headers("POST", "/compress", body, nonce="n-dup")
    verifier.verify("POST", "/compress", "", headers, body)
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_nonce_ttl_expiry_allows_reuse(key_dir, tmp_path):
    store = NonceStore(str(tmp_path / "n2.db"))
    verifier = Verifier(
        key_store=KeyStore(key_dir), nonce_store=store,
        tool_slug=TOOL_SLUG, skew_seconds=60, nonce_ttl_seconds=1,
    )
    body = b"%PDF-1.4"
    headers = signed_headers("POST", "/compress", body, nonce="n-ttl")
    verifier.verify("POST", "/compress", "", headers, body)
    time.sleep(1.1)
    verifier.verify("POST", "/compress", "", headers, body)  # expired -> allowed


def test_concurrent_same_nonce_admitted_once(key_dir, tmp_path):
    store = NonceStore(str(tmp_path / "n3.db"))
    verifier = Verifier(
        key_store=KeyStore(key_dir), nonce_store=store,
        tool_slug=TOOL_SLUG, skew_seconds=60, nonce_ttl_seconds=300,
    )
    body = b"%PDF-1.4"
    headers = signed_headers("POST", "/compress", body, nonce="n-race")
    results: list[bool] = []
    lock = threading.Lock()

    def attempt():
        try:
            verifier.verify("POST", "/compress", "", headers, body)
            ok = True
        except SignatureError:
            ok = False
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=attempt) for _ in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(results) == 1
    assert results.count(False) == 23


def test_streamed_body_with_valid_digest(key_dir, tmp_path):
    store = NonceStore(str(tmp_path / "n4.db"))
    verifier = Verifier(
        key_store=KeyStore(key_dir), nonce_store=store,
        tool_slug=TOOL_SLUG, skew_seconds=60, nonce_ttl_seconds=300,
    )
    body = b"%PDF-1.4 streamed payload"
    ts = str(int(time.time()))
    canonical = canonical_string(
        "POST", "/compress", "", ACTIVE_KEY_ID, ts, "n-stream", BODY_HASH_STREAMED
    )
    digest_value = "sha-256=" + body_hash(body)
    headers = {
        "X-Gateway": "tools-bpbj-core",
        HEADER_SIGNATURE: sign(TEST_SECRET, canonical),
        HEADER_KEY_ID: ACTIVE_KEY_ID,
        HEADER_TIMESTAMP: ts,
        HEADER_NONCE: "n-stream",
        HEADER_BODY_DIGEST: digest_value,
        HEADER_BODY_SIGNATURE: body_digest_signature(
            TEST_SECRET, canonical, digest_value
        ),
    }
    verifier.verify("POST", "/compress", "", headers, body)  # must not raise


def test_streamed_body_missing_digest_rejected(key_dir, tmp_path):
    store = NonceStore(str(tmp_path / "n5.db"))
    verifier = Verifier(
        key_store=KeyStore(key_dir), nonce_store=store,
        tool_slug=TOOL_SLUG, skew_seconds=60, nonce_ttl_seconds=300,
    )
    body = b"%PDF-1.4 streamed payload"
    ts = str(int(time.time()))
    canonical = canonical_string(
        "POST", "/compress", "", ACTIVE_KEY_ID, ts, "n-nodig", BODY_HASH_STREAMED
    )
    headers = {
        "X-Gateway": "tools-bpbj-core",
        HEADER_SIGNATURE: sign(TEST_SECRET, canonical),
        HEADER_KEY_ID: ACTIVE_KEY_ID,
        HEADER_TIMESTAMP: ts,
        HEADER_NONCE: "n-nodig",
    }
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_missing_key_file_fails_closed(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    verifier = Verifier(
        key_store=KeyStore(str(empty)),
        nonce_store=NonceStore(str(tmp_path / "n6.db")),
        tool_slug=TOOL_SLUG,
    )
    body = b"%PDF-1.4"
    headers = signed_headers("POST", "/compress", body, nonce="n-nokey")
    with pytest.raises(SignatureError):
        verifier.verify("POST", "/compress", "", headers, body)


def test_key_file_never_leaks_secret_in_error(tmp_path):
    bad = tmp_path / "keys"
    bad.mkdir()
    (bad / f"{TOOL_SLUG}.json").write_text("{not json", encoding="utf-8")
    store = KeyStore(str(bad))
    with pytest.raises(SignatureError) as exc:
        store.keys(TOOL_SLUG)
    assert "not json" not in str(exc.value)
