# PDF Compressor

A modular tool for **MyCorePlat** that compresses PDF files. Users upload a PDF
through the browser, choose a compression level, and download the compressed
result. The tool never stores documents permanently and performs no database
access.

- **Runtime:** Python 3.12 + FastAPI + Ghostscript
- **Access type:** public (internet-facing, no login)
- **Upstream:** `http://pdf-compressor:8000`
- **Repository path:** `tools/pdf-compressor/`

---

## 1. Architecture

```
Browser
  │  HTTPS
  ▼
Nginx Proxy Manager            (edge reverse proxy, TLS termination)
  │  HTTP over the shared `proxy` Docker network
  ▼
MyCorePlat Core Gateway        (auth, status checks, SSRF, HMAC signing, rate limit)
  │  HTTP over the internal `tools` Docker network
  ▼
PDF Compressor container       (this tool — HMAC verification, compression)
  │  spawns
  ▼
Ghostscript (gs -dSAFER)       (in-process subprocess, no network)
```

The tool **must not** be reachable directly from the internet. It has no
published ports; the only path in is through the Core Gateway at
`/t/pdf-compressor/...`.

Core signs **every** request it proxies to the tool with an HMAC-SHA256
signature. The tool verifies that signature and rejects anything that does not
match. HMAC is **service-to-service authentication** (Core → tool); it is
independent of user authentication. A public tool still requires a valid Core
signature.

---

## 2. API

### `GET /health`

Health check. Unsigned (polled by Core without signing).

```json
{ "status": "ok", "version": "1.0.0", "uptimeSeconds": 123 }
```

Healthy when the response is HTTP 200 **and** `status == "ok"`.

### `GET /`

The browser UI: drag-and-drop PDF upload, Low/Medium/High quality selector,
original size, result size, saving percentage, download button, and a readable
error area.

### `POST /compress`

Signed request (all five `X-Signature*` headers required).

- **Body:** `multipart/form-data` with fields `file` (the PDF) and `level`
  (`low` | `medium` | `high`).
- **Success:** `200` with `Content-Type: application/pdf`, the compressed file
  as the body, and headers:
  - `X-Original-Size` — original byte count
  - `X-Compressed-Size` — result byte count
  - `X-Saved-Percent` — integer saving percentage
  - `X-Kept-Original` — `true` when the result was not smaller (the original
    file is returned unchanged in that case)
- **Errors:** JSON `{ "success": false, "error": "<code>", "message": "<text>" }`
  with a meaningful HTTP status (`400` invalid, `401` bad signature,
  `413` too large, `429` rate limited, `503` busy, `500` compression failed).

The signature covers the **entire HTTP body** (the whole multipart envelope),
not just the file bytes.

---

## 3. Security

| Control | Implementation |
|---|---|
| HMAC verification | `app/security.py` — same canonical string as Core's `pkg/toolauth` |
| Clock skew | ±60 s (`HMAC_SKEW_SECONDS`) |
| Replay protection | SQLite `hmac_nonces` with composite primary key; atomic `INSERT OR IGNORE`; TTL 300 s |
| Fail closed | Unknown key, revoked key, missing nonce store or store error → reject |
| PDF validation | Magic bytes `%PDF-` (not just `Content-Type`) |
| Upload limit | 25 MiB (`MAX_UPLOAD_BYTES`) |
| Per-IP rate limit | 20 requests / minute (`RATE_LIMIT_PER_MINUTE`) |
| Concurrency cap | 3 simultaneous compressions (`MAX_CONCURRENCY`) → `503` + `Retry-After` |
| Processing timeout | 45 s (`PROCESSING_TIMEOUT_SECONDS`), below the gateway's 60 s response timeout |
| Ghostscript sandbox | `-dSAFER` always passed |
| Temp file isolation | Per-request `tempfile.mkdtemp(prefix="pdfc-")`, files removed in `finally` |
| No permanent storage | Nothing is written outside the temp directory |
| No database access | The tool never touches the MyCorePlat database |
| Non-root container | Runs as UID/GID 10001 |
| Read-only FS | `read_only: true` + `tmpfs: /tmp` |
| Dropped capabilities | `cap_drop: [ALL]`, `no-new-privileges` |
| Logging | Never logs tokens, signatures, or document contents |

---

## 4. Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `TOOL_SLUG` | `pdf-compressor` | Must match the slug in the DB and the HMAC key filename |
| `TOOL_HMAC_KEYS_DIR` | _(required)_ | Directory holding `<slug>.json` key files |
| `NONCE_DB_PATH` | `/tmp/nonces.db` | SQLite file for replay protection (tmpfs) |
| `HMAC_SKEW_SECONDS` | `60` | Allowed clock skew |
| `NONCE_TTL_SECONDS` | `300` | Replay-cache retention (must be ≥ 2 × skew) |
| `MAX_UPLOAD_BYTES` | `26214400` | Upload size ceiling (25 MiB) |
| `PROCESSING_TIMEOUT_SECONDS` | `45` | Ghostscript timeout |
| `RATE_LIMIT_PER_MINUTE` | `20` | Per-IP rate limit |
| `MAX_CONCURRENCY` | `3` | Simultaneous compressions |
| `GHOSTSCRIPT_BIN` | `gs` | Ghostscript executable |

### HMAC secret file

Core stores its per-tool secrets as `<TOOL_HMAC_KEYS_DIR>/<slug>.json`:

```json
{
  "toolSlug": "pdf-compressor",
  "keys": [
    { "keyId": "k-2026-11", "secret": "<base64>", "status": "active", "notAfter": null }
  ]
}
```

Generate a secret and place the file:

```bash
mkdir -p deploy/core/secrets/tool-hmac
head -c 32 /dev/urandom | base64 > /tmp/pdfc-secret.b64
# create pdf-compressor.json using the base64 value above (see deployment guide)
chmod 600 deploy/core/secrets/tool-hmac/pdf-compressor.json
```

Add `pdf-compressor` to Core's `UPSTREAM_ALLOWED_HOSTS` so the gateway accepts
the upstream hostname.

---

## 5. Registering the tool in MyCorePlat

Registration is a **data operation** — no Core source code change.

1. Import `manifest.json` through the Admin dashboard (or create the tool
   manually with the same values).
2. Set `status = active` and `access_type = public`.
3. Place the HMAC key file where Core can read it and add `pdf-compressor` to
   `UPSTREAM_ALLOWED_HOSTS`.
4. The tool becomes reachable at `https://<domain>/t/pdf-compressor/`.

`manifest.json`:

```json
{
  "id": "pdf-compressor",
  "name": "PDF Compressor",
  "version": "1.0.0",
  "description": "Compress PDF files to reduce their size using three quality levels.",
  "category": "Document",
  "access": "public",
  "runtime": "python",
  "upstream": "http://pdf-compressor:8000",
  "healthcheck": "/health",
  "displayOrder": 10,
  "icon": "file-pdf",
  "schemaVersion": "1"
}
```

---

## 6. Running locally

```bash
# unit + API tests (48 tests)
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q

# container image
docker build -t tools-bpbj/pdf-compressor:dev .

# container (development, published on loopback only)
docker run --rm -p 127.0.0.1:18099:8000 \
  -e TOOL_HMAC_KEYS_DIR=/run/secrets/tool-hmac \
  -v "$PWD/secrets/tool-hmac:/run/secrets/tool-hmac:ro" \
  --tmpfs /tmp \
  tools-bpbj/pdf-compressor:dev
```

The end-to-end smoke test (`tests/smoke_container.py`) exercises a running
container: valid signature compresses, missing signature → 401, replayed nonce
→ 401, non-PDF → 400.

```bash
python tests/smoke_container.py "$(cat /tmp/pdfc-secret.b64)"
```

---

## 7. Compression levels

| Level | Ghostscript preset | Typical use |
|---|---|---|
| `low` | `/prepress` | Print quality, minimal size reduction |
| `medium` | `/ebook` | Balanced (default) |
| `high` | `/screen` | Smallest file, screen viewing |

If a level produces a **larger** file, the original is returned and
`X-Kept-Original: true` is set.

---

## 8. Known limitations

- **Streamed-body signature path unusable over ASGI.** Core streams bodies of
  1 MiB or larger and binds them with a signed digest trailer
  (`X-Signature-Body-Digest`). ASGI/uvicorn cannot receive HTTP trailers, so
  this Python tool can only verify the **buffered** signature path. Practically
  this means uploads must stay below `GATEWAY_SIGN_BUFFER_BYTES` (1 MiB) unless
  the operator raises that Core setting (e.g. to 25 MiB) so the entire upload is
  buffered and signed with a normal body hash. Recommended: set
  `GATEWAY_SIGN_BUFFER_BYTES=26214400`.
- **Gateway response timeout.** Core's `GATEWAY_RESPONSE_HEADER_TIMEOUT` is 60 s.
  Very large or complex PDFs can exceed it; the tool caps processing at 45 s and
  returns an error, but the operator may raise the gateway timeout for heavier
  workloads.
- **Compression effectiveness.** Some PDFs (already-compressed scans, images)
  cannot be shrunk; the original is returned.
