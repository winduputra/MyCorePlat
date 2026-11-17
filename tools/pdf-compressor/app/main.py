"""PDF Compressor HTTP service.

Browser -> Nginx Proxy Manager -> MyCorePlat Core gateway -> this container.

Every request must carry a valid Core signature: "public" access means the end
user needs no account, not that the tool trusts anonymous callers. The HMAC
check happens before any work is done.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.datastructures import UploadFile

from .compressor import CompressionError, compress_pdf
from .config import Settings
from .limits import ConcurrencyGuard, RateLimiter
from .security import KeyStore, NonceStore, SignatureError, Verifier
from .validation import ValidationError, validate_level, validate_pdf, validate_size

STARTED_AT = time.time()

INDEX_HTML = """<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PDF Compressor - Tools BPBJ</title>
  <style>
    :root { --navy:#0f172a; --green:#16a34a; --slate:#64748b; --line:#e2e8f0; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; background:#f8fafc; color:var(--navy);
           font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
    .wrap { max-width: 720px; margin: 0 auto; padding: 2rem 1rem 3rem; }
    h1 { font-size: 1.5rem; margin: 0 0 .35rem; }
    p.sub { color: var(--slate); margin: 0 0 1.75rem; font-size: .95rem; }
    .card { background:#fff; border:1px solid var(--line); border-radius:12px;
            padding:1.5rem; box-shadow:0 1px 2px rgba(15,23,42,.04); }
    .drop { border:2px dashed var(--line); border-radius:10px; padding:2rem 1rem;
            text-align:center; cursor:pointer; transition:.15s; }
    .drop.over { border-color: var(--green); background:#f0fdf4; }
    .drop strong { display:block; margin-bottom:.4rem; }
    .drop span { color: var(--slate); font-size:.9rem; }
    input[type=file] { display:none; }
    .levels { display:flex; gap:.6rem; margin:1.25rem 0; flex-wrap:wrap; }
    .levels label { flex:1; min-width:120px; border:1px solid var(--line);
                    border-radius:8px; padding:.7rem .9rem; cursor:pointer;
                    font-size:.9rem; text-align:center; }
    .levels input { margin-right:.4rem; }
    .levels label:has(input:checked) { border-color:var(--green);
                    background:#f0fdf4; color:var(--green); font-weight:600; }
    button { width:100%; padding:.85rem; border:0; border-radius:8px;
             background:var(--green); color:#fff; font-size:1rem;
             font-weight:600; cursor:pointer; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    .row { display:flex; justify-content:space-between; padding:.5rem 0;
           font-size:.92rem; border-bottom:1px solid var(--line); }
    .row:last-child { border-bottom:0; }
    .row b { font-variant-numeric: tabular-nums; }
    .ok { color: var(--green); font-weight:600; }
    .err { background:#fef2f2; border:1px solid #fecaca; color:#b91c1c;
           border-radius:8px; padding:.85rem 1rem; margin-top:1rem; font-size:.9rem; }
    a.dl { display:block; margin-top:1rem; text-align:center; padding:.8rem;
           background:var(--navy); color:#fff; border-radius:8px;
           text-decoration:none; font-weight:600; }
    .hidden { display:none; }
    .hint { color:var(--slate); font-size:.8rem; margin-top:1rem; text-align:center; }
  </style>
</head>
<body>
<div class="wrap">
  <h1>PDF Compressor</h1>
  <p class="sub">Perkecil ukuran berkas PDF tanpa mengubah isi dokumen.</p>

  <div class="card">
    <label class="drop" id="drop" for="file">
      <strong id="dropTitle">Tarik berkas PDF ke sini</strong>
      <span id="dropHint">atau klik untuk memilih berkas (maks. 25 MiB)</span>
    </label>
    <input type="file" id="file" accept="application/pdf,.pdf">

    <div class="levels">
      <label><input type="radio" name="level" value="low">Low</label>
      <label><input type="radio" name="level" value="medium" checked>Medium</label>
      <label><input type="radio" name="level" value="high">High</label>
    </div>

    <button id="submit" disabled>Kompres PDF</button>
    <div id="error" class="err hidden"></div>

    <div id="result" class="hidden" style="margin-top:1.25rem">
      <div class="row"><span>Ukuran awal</span><b id="origSize">-</b></div>
      <div class="row"><span>Ukuran hasil</span><b id="newSize">-</b></div>
      <div class="row"><span>Penghematan</span><b id="saving" class="ok">-</b></div>
      <a class="dl" id="download" href="#" download>Unduh PDF hasil</a>
    </div>
    <p class="hint">Berkas Anda tidak disimpan. Semua berkas sementara dihapus setelah diproses.</p>
  </div>
</div>
<script>
(function () {
  var drop = document.getElementById('drop');
  var input = document.getElementById('file');
  var submit = document.getElementById('submit');
  var errorBox = document.getElementById('error');
  var result = document.getElementById('result');
  var downloadLink = document.getElementById('download');
  var currentBlobUrl = null;

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove('hidden');
  }

  function clearError() {
    errorBox.textContent = '';
    errorBox.classList.add('hidden');
  }

  input.addEventListener('change', function () {
    clearError();
    result.classList.add('hidden');
    if (input.files.length) {
      document.getElementById('dropTitle').textContent = input.files[0].name;
      document.getElementById('dropHint').textContent =
        formatBytes(input.files[0].size);
      submit.disabled = false;
    }
  });

  ['dragenter', 'dragover'].forEach(function (name) {
    drop.addEventListener(name, function (e) {
      e.preventDefault();
      drop.classList.add('over');
    });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    drop.addEventListener(name, function (e) {
      e.preventDefault();
      drop.classList.remove('over');
    });
  });
  drop.addEventListener('drop', function (e) {
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event('change'));
    }
  });

  submit.addEventListener('click', function () {
    if (!input.files.length) return;
    clearError();
    result.classList.add('hidden');
    submit.disabled = true;
    submit.textContent = 'Memproses...';

    var level = document.querySelector('input[name=level]:checked').value;
    var form = new FormData();
    form.append('file', input.files[0]);
    form.append('level', level);

    fetch('/compress', { method: 'POST', body: form })
      .then(function (res) {
        if (!res.ok) {
          return res.json().catch(function () { return {}; })
            .then(function (body) {
              throw new Error(body.message || body.error ||
                'Kompresi gagal (' + res.status + ').');
            });
        }
        return res.blob().then(function (blob) {
          return { blob: blob, headers: res.headers };
        });
      })
      .then(function (out) {
        var originalSize = parseInt(out.headers.get('X-Original-Size') || '0', 10);
        var newSize = parseInt(out.headers.get('X-Compressed-Size') || '0', 10);
        var kept = out.headers.get('X-Kept-Original') === 'true';

        if (currentBlobUrl) URL.revokeObjectURL(currentBlobUrl);
        currentBlobUrl = URL.createObjectURL(out.blob);
        downloadLink.href = currentBlobUrl;

        document.getElementById('origSize').textContent = formatBytes(originalSize);
        document.getElementById('newSize').textContent = formatBytes(newSize);
        var saved = originalSize > 0
          ? Math.round((1 - newSize / originalSize) * 100) : 0;
        document.getElementById('saving').textContent = kept
          ? 'Tidak ada penghematan (berkas asli dikembalikan)'
          : saved + '%';
        document.getElementById('saving').className = kept ? '' : 'ok';
        result.classList.remove('hidden');
      })
      .catch(function (err) { showError(err.message); })
      .then(function () {
        submit.disabled = false;
        submit.textContent = 'Kompres PDF';
      });
  });
})();
</script>
</body>
</html>
"""


def _error(status: int, code: str, message: str, headers: dict | None = None):
    return JSONResponse(
        status_code=status,
        content={"success": False, "error": code, "message": message},
        headers=headers,
    )


def _build_verifier(settings: Settings) -> Verifier:
    return Verifier(
        key_store=KeyStore(settings.hmac_keys_dir),
        nonce_store=NonceStore(settings.nonce_db_path),
        tool_slug=settings.tool_slug,
        skew_seconds=settings.hmac_skew_seconds,
        nonce_ttl_seconds=settings.nonce_ttl_seconds,
    )


def create_app(settings: Settings | None = None, verifier: Verifier | None = None) -> FastAPI:
    """Build the ASGI app. Tests inject a verifier and stub compressor."""
    cfg = settings or Settings.from_env()
    active_verifier = verifier or _build_verifier(cfg)
    limiter = RateLimiter(cfg.rate_limit_per_minute)
    guard = ConcurrencyGuard(cfg.max_concurrency)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield

    app = FastAPI(title="PDF Compressor", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = cfg
    app.state.verifier = active_verifier
    app.state.limiter = limiter
    app.state.guard = guard

    def client_ip(request: Request) -> str:
        """The address Core reports. Core is the only caller, and it never
        forwards a client-supplied X-Forwarded-For without validating it."""
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def authorize(request: Request, body: bytes) -> None:
        """Verify the Core signature. Raises SignatureError on any failure."""
        url = request.url
        active_verifier.verify(
            method=request.method,
            path=url.path,
            query=url.query.decode() if isinstance(url.query, bytes) else url.query,
            headers={k.lower(): v for k, v in request.headers.items()},
            body=body,
        )

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "version": "1.0.0",
            "uptimeSeconds": int(time.time() - STARTED_AT),
        }

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(INDEX_HTML)

    @app.post("/compress")
    async def compress(request: Request):
        ip = client_ip(request)
        if not limiter.allow(ip):
            return _error(
                429,
                "rate_limited",
                "Terlalu banyak permintaan. Silakan coba lagi nanti.",
                {"Retry-After": str(limiter.retry_after_seconds())},
            )

        body = await request.body()
        try:
            await authorize(request, body)
        except SignatureError:
            # Never reveal which check failed.
            return _error(401, "unauthorized", "Permintaan tidak sah.")

        if not guard.try_acquire():
            return _error(
                503,
                "busy",
                "Server sedang sibuk. Silakan coba beberapa saat lagi.",
                {"Retry-After": "5"},
            )

        try:
            try:
                form = await request.form()
            except Exception:
                return _error(400, "invalid_request", "Permintaan tidak valid.")

            upload = form.get("file")
            level_raw = form.get("level", "medium")
            level_str = level_raw if isinstance(level_raw, str) else "medium"

            if not isinstance(upload, UploadFile):
                return _error(400, "missing_file", "Berkas PDF wajib diunggah.")

            try:
                level = validate_level(level_str)
                content = await upload.read()
                validate_size(len(content), cfg.max_upload_bytes)
                validate_pdf(content)
            except ValidationError as exc:
                return _error(exc.status_code, "validation_failed", exc.message)

            try:
                result = compress_pdf(
                    content,
                    level,
                    timeout_seconds=cfg.processing_timeout_seconds,
                    ghostscript_bin=cfg.ghostscript_bin,
                )
            except CompressionError as exc:
                return _error(422, "compression_failed", str(exc))

            saving = 0
            if result.original_size > 0:
                saving = round(
                    (1 - result.compressed_size / result.original_size) * 100, 1
                )
            return Response(
                content=result.content,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": 'attachment; filename="compressed.pdf"',
                    "X-Original-Size": str(result.original_size),
                    "X-Compressed-Size": str(result.compressed_size),
                    "X-Saved-Percent": str(saving),
                    "X-Kept-Original": "true" if result.kept_original else "false",
                    "Cache-Control": "no-store",
                },
            )
        finally:
            guard.release()

    return app


app = create_app()
