"""Test helpers: build requests signed exactly the way Core signs them."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

ACTIVE_KEY_ID = "k-active"
PREVIOUS_KEY_ID = "k-previous"
REVOKED_KEY_ID = "k-revoked"
TEST_SECRET = b"unit-test-secret-key-32-bytes-ok"
TOOL_SLUG = "pdf-compressor"


def canonical(method, path, query, key_id, timestamp, nonce, body_hash):
    return "\n".join([method, path, query, key_id, timestamp, nonce, body_hash])


def sign(secret: bytes, canonical_str: str) -> str:
    return hmac.new(secret, canonical_str.encode(), hashlib.sha256).hexdigest()


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def write_key_file(directory: str, slug: str = TOOL_SLUG) -> str:
    """Write a key file in Core's FileKeyStore format and return its path."""
    payload = {
        "toolSlug": slug,
        "keys": [
            {
                "keyId": ACTIVE_KEY_ID,
                "secret": base64.b64encode(TEST_SECRET).decode(),
                "status": "active",
            },
            {
                "keyId": PREVIOUS_KEY_ID,
                "secret": base64.b64encode(b"previous-secret-key-32-bytes!!").decode(),
                "status": "previous",
                "notAfter": "2099-01-01T00:00:00Z",
            },
            {
                "keyId": REVOKED_KEY_ID,
                "secret": base64.b64encode(b"revoked-secret-key-32-bytes!!!").decode(),
                "status": "revoked",
            },
        ],
    }
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{slug}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


def signed_headers(
    method: str,
    path: str,
    body: bytes,
    secret: bytes = TEST_SECRET,
    key_id: str = ACTIVE_KEY_ID,
    timestamp: int | None = None,
    nonce: str = "nonce-0001",
    query: str = "",
) -> dict[str, str]:
    """Return the signature headers Core would send for this request."""
    ts = str(int(time.time()) if timestamp is None else timestamp)
    canonical_str = canonical(method, path, query, key_id, ts, nonce, body_hash(body))
    return {
        "X-Gateway": "tools-bpbj-core",
        "X-Signature": sign(secret, canonical_str),
        "X-Signature-Key-Id": key_id,
        "X-Signature-Timestamp": ts,
        "X-Signature-Nonce": nonce,
    }
