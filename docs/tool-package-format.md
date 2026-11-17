# Format Paket Tool MyCorePlat

Dokumen ini menjelaskan format **ZIP paket tool** yang dapat diunggah administrator
melalui dashboard MyCorePlat (menu **Installer**). Setelah paket diunggah, sistem
secara otomatis memvalidasi, membangun image, menjalankan container, membuat
secret HMAC, dan mendaftarkan tool ke database serta Gateway.

**Menambah tool baru TIDAK memerlukan perubahan source code Core, edit konfigurasi
server manual, atau rebuild Core.**

---

## 1. Alur singkat

```
Buat ZIP  →  Login Admin  →  Upload ZIP (menu Installer)  →  Install  →  Aktifkan
```

| Tahap | Siapa | Apa yang terjadi |
|---|---|---|
| 1 | Developer | Menulis tool + `manifest.json` + `Dockerfile`, lalu membuat ZIP |
| 2 | Admin | Login ke `/admin/login` |
| 3 | Admin | Buka **Installer**, unggah ZIP |
| 4 | Sistem | Validasi paket → build image → buat secret HMAC → jalankan container → cek health → daftarkan tool (status `draft`) |
| 5 | Admin | Tekan **Aktifkan** → tool menjadi `active` dan dapat diakses di `/t/<slug>/` |

Jika salah satu tahap 4 gagal, sistem melakukan **rollback**: container dihentikan,
image dihapus, secret dicabut, dan tool tidak didaftarkan. Tool lain tidak terpengaruh.

---

## 2. Struktur ZIP

Isi ZIP berada di **root arsip** (bukan di dalam satu folder pembungkus), karena
arsip tersebut langsung dipakai sebagai *Docker build context*.

```
paket-tool.zip
├── manifest.json          (WAJIB)
├── Dockerfile             (WAJIB)
├── requirements.txt       (contoh; bebas sesuai runtime)
└── app/
    ├── main.py
    └── ...
```

### 2.1 File wajib

| File | Keterangan |
|---|---|
| `manifest.json` | Metadata tool (lihat §3) |
| `Dockerfile` | Cara membangun image. Harus dapat di-build dari root konteks ZIP |

Tanpa salah satu file ini, paket **ditolak** sebelum ada yang dijalankan.

### 2.2 Yang sebaiknya TIDAK dimasukkan

| Item | Alasan |
|---|---|
| `.env`, file secret, kunci privat | Tidak boleh ikut ke image |
| `tests/`, cache (`__pycache__`, `.pytest_cache`) | Memperbesar paket, tidak dipakai runtime |
| `.git/`, `.venv/`, `node_modules/` | Ukuran besar, tidak relevan |
| `docker-compose.yml`, `README.md` | Tidak diperlukan installer |

Script `tools/package-tool.ps1` sudah mengecualikan item-item di atas secara otomatis.

### 2.3 Cara membuat ZIP (disarankan)

```powershell
pwsh tools/package-tool.ps1 -ToolDir tools/pdf-compressor -OutDir dist
# -> packaged: dist/pdf-compressor-1.0.0.zip (16037 bytes)
```

Atau manual — pastikan `manifest.json` dan `Dockerfile` berada di root ZIP:

```bash
cd tools/my-tool
zip -r ../../dist/my-tool-1.0.0.zip manifest.json Dockerfile app requirements.txt
```

---

## 3. manifest.json

Contoh lengkap:

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

### 3.1 Aturan setiap field

| Field | Wajib | Aturan |
|---|---|---|
| `id` | Ya | Slug unik: huruf kecil, angka, tanda hubung tunggal. Pola `^[a-z0-9]+(?:-[a-z0-9]+)*$`, maks 63 karakter. **Menjadi slug URL** `/t/<id>/` |
| `name` | Ya | 1–128 karakter, nama tampilan |
| `version` | Ya | Semver penuh, mis. `1.0.0`, `2.1.3-rc1` |
| `description` | Ya | 1–512 karakter |
| `category` | Tidak | Maks 64 karakter |
| `access` | Ya | `public` (tanpa login) atau `token` (butuh access token) |
| `runtime` | Ya | Salah satu: `python`, `php`, `node`, `go` |
| `upstream` | Ya | URL internal tempat container mendengarkan. Host **harus** ada di `INSTALLER_UPSTREAM_ALLOWED_HOSTS` (installer) dan `UPSTREAM_ALLOWED_HOSTS` (Core) |
| `healthcheck` | Ya | Path yang dimulai dengan `/`, mis. `/health`. Dipakai installer untuk menunggu container siap |
| `displayOrder` | Tidak | Bilangan bulat ≥ 0, urutan di katalog |
| `icon` | Tidak | Maks 64 karakter, nama ikon |
| `schemaVersion` | Tidak | Maks 16 karakter |

**Field yang tidak dikenal akan ditolak** (validasi ketat). Field `status` dan
pengaturan keamanan **tidak boleh** ada di manifest — status selalu ditentukan
admin melalui dashboard, dan tool hasil instalasi selalu mulai dari `draft`.

### 3.2 Field `upstream`

`upstream` adalah alamat yang dipakai Core untuk meneruskan permintaan. Nilainya
harus berupa **hostname internal** (nama service), bukan `localhost` atau IP publik:

```
http://pdf-compressor:8000     ✔ benar
http://localhost:8000          ✘ ditolak (loopback)
http://8.8.8.8:8000            ✘ ditolak (alamat publik)
```

Installer otomatis menambahkan hostname ini sebagai **network alias** container,
sehingga `http://pdf-compressor:8000` dapat di-resolve di jaringan `tools` meskipun
nama container sebenarnya memiliki akhiran unik.

Port yang diizinkan: `80`, `443`, `3000`, `5000`, `8000`, `8080`, `8443`, `9000`
(atau tanpa port).

---

## 4. Kontrak HTTP tool

### 4.1 Endpoint wajib

| Endpoint | Keterangan |
|---|---|
| `GET <healthcheck>` | Wajib. Kembalikan **HTTP 200** dengan JSON `{"status":"ok", ...}`. Installer menunggu endpoint ini sebelum menandai instalasi berhasil |

### 4.2 Endpoint fungsional

Semua route tool diakses melalui Gateway: `https://<domain>/t/<id>/<path>`.
Core akan meneruskan ke `http://<upstream-host>:<port>/<path>`.

Contoh: `GET /t/pdf-compressor/health` → `GET http://pdf-compressor:8000/health`.

### 4.3 Header dari Core

Setiap permintaan yang diteruskan Core **ditandatangani HMAC-SHA256** dan membawa:

| Header | Isi |
|---|---|
| `X-Gateway` | `tools-bpbj-core` |
| `X-Signature-Key-Id` | ID kunci aktif |
| `X-Signature-Timestamp` | Unix epoch detik |
| `X-Signature-Nonce` | Nonce acak per permintaan |
| `X-Signature` | HMAC-SHA256 hex |

String kanonik yang ditandatangani:

```
METHOD \n path \n query \n keyId \n timestamp \n nonce \n bodyHash
```

`bodyHash` = SHA-256 hex dari **seluruh body HTTP** (untuk upload, ini adalah
seluruh envelope multipart, bukan hanya file-nya).

### 4.4 Kewajiban tool

Tool **WAJIB**:

1. Memverifikasi tanda tangan (bandingkan dengan constant-time).
2. Menolak timestamp di luar ±60 detik.
3. Menolak `keyId` yang tidak dikenal, dicabut, atau kedaluwarsa.
4. Menolak nonce yang sudah dipakai (replay protection **atomik**, TTL ≥ 120 detik).
5. Menolak jika terjadi kesalahan penyimpanan nonce (**fail closed**).

Tool yang tidak memverifikasi tanda tangan **tidak memenuhi syarat** dan akan
menerima permintaan palsu dari dalam jaringan.

> HMAC adalah autentikasi **antar-service** (Core → tool), bukan autentikasi
> pengguna. Tool `public` tetap memerlukan tanda tangan Core yang sah.

Referensi implementasi:
- Go: `pkg/toolauth` di repository ini.
- Python: `tools/pdf-compressor/app/security.py`.

---

## 5. Secret HMAC

Installer membuat secret HMAC secara otomatis saat instalasi dan menuliskannya ke
direktori yang dibagi dengan Core:

```
<TOOL_HMAC_KEYS_DIR>/<id>.json
```

```json
{
  "toolSlug": "pdf-compressor",
  "keys": [
    { "keyId": "k-20261117-1234567890", "secret": "<base64>", "status": "active" }
  ]
}
```

- File ditulis dengan mode `0644` agar proses Core (UID berbeda) dapat membacanya;
  direktori bersifat `0755`. Kerahasiaan dijaga oleh volume yang hanya dipasang ke
  Core dan installer.
- Tool menerima direktori ini sebagai mount **read-only** di `/run/secrets/tool-hmac`.
- Saat uninstall, secret dicabut (file dihapus).
- **Secret tidak pernah ditampilkan di dashboard, log, atau respons API.**

Variabel lingkungan yang biasanya disediakan installer untuk container tool:

| Variabel | Nilai |
|---|---|
| `TOOL_SLUG` | `<id>` dari manifest |
| `TOOL_HMAC_KEYS_DIR` | `/run/secrets/tool-hmac` |

---

## 6. Dockerfile

Image dibangun otomatis dari ZIP. Persyaratan:

1. **Multi-stage** bila memungkinkan; runtime tidak boleh memuat compiler.
2. **Non-root**: set `USER` ke UID/GID tak istimewa.
3. Dengarkan pada port yang sesuai dengan `upstream` di manifest.
4. Jangan menyalin secret ke dalam image.
5. Gunakan `ENTRYPOINT`/`CMD` bentuk exec agar SIGTERM diterima.

Kebijakan yang **diterapkan paksa oleh installer** (tidak dapat dilonggarkan oleh
Dockerfile):

| Kontrol | Nilai |
|---|---|
| Root filesystem | read-only |
| `/tmp` | tmpfs (rw, noexec, nosuid, 256 MB) |
| Capabilities | semua dibuang (`cap_drop: ALL`) |
| Privilege escalation | `no-new-privileges` |
| Memori | 512 MiB (dapat diatur installer) |
| CPU | 1.0 core |
| PID | 128 |
| Jaringan | hanya jaringan internal `tools`; tidak ada port yang dipublikasikan |
| Restart policy | `unless-stopped` |

Container tool **tidak** mendapat akses Docker socket, tidak dapat keluar ke
internet (jaringan `internal: true`), dan tidak dapat diakses langsung dari luar —
satu-satunya jalur masuk adalah Gateway.

---

## 7. Batas dan validasi paket

| Batas | Nilai | Perilaku jika dilanggar |
|---|---|---|
| Ukuran ZIP terunggah | 64 MiB | Ditolak `package_too_large` (HTTP 413) |
| Ukuran isi setelah diekstrak | 256 MiB | Ditolak (deteksi zip bomb) |
| Jumlah entri | 2048 | Ditolak |
| Panjang path entri | 200 karakter | Ditolak |

**Aturan path (anti zip-slip)** — entri ditolak bila:

- path absolut (`/etc/passwd`),
- memuat `..` di segmen mana pun (`../evil`, `a/../../evil`),
- memakai backslash (`\windows\evil`),
- memuat huruf drive (`C:/...`),
- memuat segmen kosong atau `.` (`a//b`, `./x`).

File diekstrak dengan mode `0644`; bit executable dari arsip tidak dipertahankan.

---

## 8. Pengujian wajib sebelum mengirim paket

1. `GET <healthcheck>` mengembalikan 200 dan `{"status":"ok"}`.
2. Permintaan tanpa tanda tangan → 401.
3. Permintaan dengan tanda tangan salah → 401.
4. Nonce yang sama dipakai dua kali → 401 (replay ditolak).
5. Body yang diubah setelah ditandatangani → 401.
6. Build Docker berhasil dan container berjalan sebagai non-root.
7. Container tetap berfungsi dengan root filesystem read-only.

Tool contoh `tools/pdf-compressor/` memenuhi semua persyaratan di atas dan
menyertakan 48 unit test serta satu smoke test kontainer
(`tests/smoke_container.py`) yang dapat dijadikan acuan.

---

## 9. Referensi cepat

| Pertanyaan | Jawaban |
|---|---|
| Perlu ubah kode Core? | **Tidak** |
| Perlu rebuild Core? | **Tidak** |
| Perlu edit config server manual? | **Tidak** (kecuali menambah hostname ke allowlist sekali saat pertama kali) |
| Siapa yang membangun image? | Installer (satu-satunya komponen dengan akses Docker) |
| Status awal tool | `draft` — admin harus menekan **Aktifkan** |
| URL setelah aktif | `https://<domain>/t/<id>/` |
| Log tool | `docker logs tools-<id>-*` |
