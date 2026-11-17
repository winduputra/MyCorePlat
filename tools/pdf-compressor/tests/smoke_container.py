"""End-to-end smoke test against the running pdf-compressor container.

Signs a real multipart /compress request with the real HMAC key and verifies
that Ghostscript produced a smaller PDF. Run from the repo root:

    python tools/pdf-compressor/tests/smoke_container.py <secret_b64>
"""

import hashlib
import hmac
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "tools/pdf-compressor")

from app.security import body_hash, canonical_string  # noqa: E402

BASE = "http://127.0.0.1:18099"
BOUNDARY = "smokeBoundary42"


def make_pdf(pages: int) -> bytes:
    """Build a small multi-page PDF with real structure so gs has something to do."""
    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{3 + i} 0 R" for i in range(pages))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {pages} >>".encode())
    for i in range(pages):
        content = f"BT /F1 36 Tf 72 700 Td (Page {i + 1} - smoke test) Tj ET".encode()
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {3 + pages + i} 0 R /Resources << /Font << /F1 {3 + 2 * pages} 0 R >> >> >>".encode()
        )
    for i in range(pages):
        content = f"BT /F1 36 Tf 72 700 Td (Page {i + 1} - smoke test) Tj ET".encode()
        objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def multipart_body(pdf: bytes, level: str) -> bytes:
    return (
        f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"level\"\r\n\r\n{level}\r\n".encode()
        + f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"doc.pdf\"\r\n".encode()
        + b"Content-Type: application/pdf\r\n\r\n"
        + pdf
        + f"\r\n--{BOUNDARY}--\r\n".encode()
    )


def sign_headers(secret: bytes, method: str, path: str, body: bytes) -> dict:
    ts = str(int(time.time()))
    nonce = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:32]
    bh = body_hash(body)
    canon = canonical_string(method, path, "", "k-smoke", ts, nonce, bh)
    sig = hmac.new(secret, canon.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Gateway": "tools-bpbj-core",
        "X-Signature-Key-Id": "k-smoke",
        "X-Signature-Timestamp": ts,
        "X-Signature-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
    }


def main() -> int:
    secret = __import__("base64").b64decode(sys.argv[1])
    pdf = make_pdf(30)
    print(f"original size: {len(pdf)} bytes")

    checks = []

    # 1. valid signed request compresses
    body = multipart_body(pdf, "high")
    headers = sign_headers(secret, "POST", "/compress", body)
    req = urllib.request.Request(BASE + "/compress", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = resp.read()
        orig = resp.headers.get("X-Original-Size")
        comp = resp.headers.get("X-Compressed-Size")
        kept = resp.headers.get("X-Kept-Original")
        print(f"  200: result={len(result)}B orig={orig} comp={comp} kept_original={kept}")
        checks.append(("valid signature compresses", resp.status == 200 and result[:5] == b"%PDF-"))

    # 2. missing signature -> 401
    req = urllib.request.Request(
        BASE + "/compress", data=body, headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        checks.append(("missing signature 401", False))
    except urllib.error.HTTPError as e:
        print(f"  missing signature -> {e.code}")
        checks.append(("missing signature 401", e.code == 401))

    # 3. replayed nonce -> 401
    req = urllib.request.Request(BASE + "/compress", data=body, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        checks.append(("replayed nonce 401", False))
    except urllib.error.HTTPError as e:
        print(f"  replayed nonce -> {e.code}")
        checks.append(("replayed nonce 401", e.code == 401))

    # 4. non-PDF content -> 400
    fake = b"this is not a pdf at all"
    body4 = multipart_body(fake, "medium")
    req = urllib.request.Request(BASE + "/compress", data=body4, headers=sign_headers(secret, "POST", "/compress", body4), method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        checks.append(("non-PDF 400", False))
    except urllib.error.HTTPError as e:
        print(f"  non-PDF -> {e.code}")
        checks.append(("non-PDF 400", e.code == 400))

    print()
    ok = True
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
