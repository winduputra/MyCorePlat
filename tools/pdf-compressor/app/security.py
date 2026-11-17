"""HMAC verification for Core -> Tool requests.

This is a faithful Python port of the Go reference implementation in
``pkg/toolauth``. The wire contract is fixed:

    canonical = METHOD \\n path \\n query \\n keyId \\n timestamp \\n nonce \\n bodyHash
    signature = lowercase hex HMAC-SHA256(secret, canonical)

A request is accepted only when ALL of the following hold:

* the four signature headers are present,
* the key id is known and not revoked,
* the key is still within its optional rotation deadline,
* the HMAC matches (constant time),
* the timestamp is inside the skew window,
* for a streamed body, the signed digest trailer matches the received bytes,
* the keyId+nonce pair has never been seen before (atomic, TTL bounded).

Any failure means the request MUST be rejected; nothing is processed and no
detail about the reason is returned to the caller.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

# Header names (must match pkg/toolauth/doc.go exactly).
HEADER_GATEWAY = "X-Gateway"
HEADER_SIGNATURE = "X-Signature"
HEADER_KEY_ID = "X-Signature-Key-Id"
HEADER_TIMESTAMP = "X-Signature-Timestamp"
HEADER_NONCE = "X-Signature-Nonce"
HEADER_BODY_DIGEST = "X-Signature-Body-Digest"
HEADER_BODY_SIGNATURE = "X-Signature-Body-Sig"

GATEWAY_IDENTIFIER = "tools-bpbj-core"
BODY_HASH_STREAMED = "streamed"
EMPTY_BODY_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

DEFAULT_SKEW_SECONDS = 60
DEFAULT_NONCE_TTL_SECONDS = 120
MIN_SECRET_BYTES = 16

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class SignatureError(Exception):
    """Raised when a request fails verification. Message is safe to log."""


def canonical_string(
    method: str,
    path: str,
    query: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    body_hash: str,
) -> str:
    """Build the exact string Core signs and the tool verifies."""
    return "\n".join([method, path, query, key_id, timestamp, nonce, body_hash])


def body_hash(body: bytes) -> str:
    """Lowercase hex SHA-256 of the exact body bytes."""
    return hashlib.sha256(body).hexdigest()


def _sign(secret: bytes, canonical: str) -> str:
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def body_digest_signature(secret: bytes, canonical: str, digest_value: str) -> str:
    """Signature over the canonical string plus the streamed digest value."""
    return _sign(secret, canonical + "\n" + digest_value)


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    secret: bytes
    status: str
    not_after: datetime | None = None

    def usable(self, now: datetime) -> bool:
        if self.status == "revoked":
            return False
        if self.not_after is not None and not now < self.not_after:
            return False
        return True


class KeySet:
    """Immutable collection of signing keys addressed by key id."""

    def __init__(self, keys: list[SigningKey]) -> None:
        seen: dict[str, SigningKey] = {}
        for key in keys:
            if key.key_id in seen:
                raise SignatureError("duplicate key id")
            seen[key.key_id] = key
        self._keys = seen

    def lookup(self, key_id: str) -> SigningKey | None:
        return self._keys.get(key_id)


def load_key_file(path: str) -> KeySet:
    """Load a per-tool key file (same JSON shape Core's FileKeyStore writes).

    The file is read fresh on every call so key rotation only needs a file
    update, never a restart. Contents are never echoed in errors.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parsed = json.load(handle)
    except FileNotFoundError as exc:
        raise SignatureError("key file not found") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SignatureError("key file unavailable") from exc

    keys: list[SigningKey] = []
    for entry in parsed.get("keys", []):
        try:
            secret = base64.b64decode(entry["secret"], validate=True)
        except (KeyError, ValueError) as exc:
            raise SignatureError("key file has an invalid secret") from exc
        if len(secret) < MIN_SECRET_BYTES:
            raise SignatureError("key secret too short")
        status = entry.get("status", "")
        if status not in ("active", "previous", "revoked"):
            raise SignatureError("key has invalid status")
        not_after = _parse_not_after(entry.get("notAfter"))
        keys.append(SigningKey(entry["keyId"], secret, status, not_after))
    return KeySet(keys)


def _parse_not_after(raw: object) -> datetime | None:
    if not raw:
        return None
    text = str(raw)
    # Go's time.Time marshals as RFC3339 with a trailing Z.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SignatureError("key has an invalid notAfter") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class KeyStore:
    """Resolves the key set for a tool slug from a directory of key files."""

    def __init__(self, directory: str) -> None:
        self._directory = directory
        self._lock = threading.Lock()

    def keys(self, tool_slug: str) -> KeySet:
        if not self._directory or not _SLUG_PATTERN.match(tool_slug):
            raise SignatureError("key store unavailable")
        with self._lock:
            path = os.path.join(self._directory, f"{tool_slug}.json")
            return load_key_file(path)


class NonceStore:
    """Atomic, TTL-bounded replay protection backed by SQLite.

    ``check_and_store`` inserts the keyId+nonce pair under a UNIQUE constraint
    in a single transaction, so two concurrent requests carrying the same pair
    cannot both succeed. Entries older than the TTL are pruned on write.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # Ensure the parent directory exists so a configured path inside a
        # mounted volume (or a fresh tmpfs) does not fail at startup.
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hmac_nonces (
                    key_id     TEXT NOT NULL,
                    nonce      TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (key_id, nonce)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nonce_expires ON hmac_nonces (expires_at)"
            )

    def check_and_store(self, key_id: str, nonce: str, ttl_seconds: int) -> None:
        """Record the pair once.

        Returns normally on the first sighting. Raises ``SignatureError`` for a
        replay and any storage failure, so the caller always fails closed.
        """
        if ttl_seconds <= 0:
            ttl_seconds = DEFAULT_NONCE_TTL_SECONDS
        now = time.time()
        try:
            with self._lock, self._connect() as conn:
                conn.execute("DELETE FROM hmac_nonces WHERE expires_at <= ?", (now,))
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO hmac_nonces (key_id, nonce, expires_at) "
                    "VALUES (?, ?, ?)",
                    (key_id, nonce, now + ttl_seconds),
                )
                if cursor.rowcount == 0:
                    raise SignatureError("nonce reused")
        except sqlite3.Error as exc:
            raise SignatureError("nonce store unavailable") from exc


class Verifier:
    """Verifies a single inbound request against the fixed contract."""

    def __init__(
        self,
        key_store: KeyStore,
        nonce_store: NonceStore,
        tool_slug: str,
        skew_seconds: int = DEFAULT_SKEW_SECONDS,
        nonce_ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS,
        now_fn=time.time,
    ) -> None:
        self._key_store = key_store
        self._nonce_store = nonce_store
        self._tool_slug = tool_slug
        self._skew = skew_seconds if skew_seconds > 0 else DEFAULT_SKEW_SECONDS
        self._nonce_ttl = (
            nonce_ttl_seconds if nonce_ttl_seconds > 0 else DEFAULT_NONCE_TTL_SECONDS
        )
        self._now = now_fn

    def verify(
        self,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        """Raise SignatureError unless the request is authentic and fresh.

        ``body`` must be the exact bytes received; the digest trailer (when the
        body was streamed) is read from the headers, which is where httpx/ASGI
        expose trailing headers after the body has been read.
        """
        normalized = {k.lower(): v for k, v in headers.items()}
        signature = normalized.get(HEADER_SIGNATURE.lower(), "").strip()
        key_id = normalized.get(HEADER_KEY_ID.lower(), "").strip()
        timestamp_raw = normalized.get(HEADER_TIMESTAMP.lower(), "").strip()
        nonce = normalized.get(HEADER_NONCE.lower(), "").strip()
        if not signature or not key_id or not timestamp_raw or not nonce:
            raise SignatureError("missing signature headers")
        try:
            timestamp = int(timestamp_raw)
        except ValueError as exc:
            raise SignatureError("invalid timestamp") from exc

        keys = self._key_store.keys(self._tool_slug)
        key = keys.lookup(key_id)
        if key is None:
            raise SignatureError("unknown key id")
        if key.status == "revoked":
            raise SignatureError("revoked key")
        if not key.usable(datetime.now(timezone.utc)):
            raise SignatureError("expired key")

        received_hash = body_hash(body)
        streamed = False
        buffered_canonical = canonical_string(
            method, path, query, key_id, timestamp_raw, nonce, received_hash
        )
        expected = _sign(key.secret, buffered_canonical)
        if not hmac.compare_digest(signature, expected):
            streamed_canonical = canonical_string(
                method, path, query, key_id, timestamp_raw, nonce, BODY_HASH_STREAMED
            )
            if not hmac.compare_digest(
                signature, _sign(key.secret, streamed_canonical)
            ):
                raise SignatureError("signature mismatch")
            streamed = True

        now = self._now()
        if abs(now - timestamp) > self._skew:
            raise SignatureError("timestamp out of range")

        if streamed:
            self._verify_streamed_digest(key, method, path, query, key_id,
                                         timestamp_raw, nonce, received_hash, headers)

        self._nonce_store.check_and_store(key_id, nonce, self._nonce_ttl)

    def _verify_streamed_digest(
        self,
        key: SigningKey,
        method: str,
        path: str,
        query: str,
        key_id: str,
        timestamp_raw: str,
        nonce: str,
        received_hash: str,
        headers: dict[str, str],
    ) -> None:
        normalized = {k.lower(): v for k, v in headers.items()}
        digest_value = normalized.get(HEADER_BODY_DIGEST.lower(), "").strip()
        digest_sig = normalized.get(HEADER_BODY_SIGNATURE.lower(), "").strip()
        if not digest_value or not digest_sig:
            raise SignatureError("missing body digest")
        expected_digest = "sha-256=" + received_hash
        if not hmac.compare_digest(digest_value, expected_digest):
            raise SignatureError("body hash mismatch")
        canonical = canonical_string(
            method, path, query, key_id, timestamp_raw, nonce, BODY_HASH_STREAMED
        )
        expected_sig = body_digest_signature(key.secret, canonical, digest_value)
        if not hmac.compare_digest(digest_sig, expected_sig):
            raise SignatureError("signature mismatch")
