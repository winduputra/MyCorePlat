# Panduan Deployment — Tools BPBJ (Core)

Dokumen ini menjelaskan cara melakukan deployment **Core Portal Tools BPBJ** ke server
production, termasuk prasyarat, konfigurasi, build, migrasi database, integrasi Nginx
Proxy Manager (NPM), backup/restore, pembaruan, troubleshooting, dan prosedur recovery.

> **Penting:** Dokumen ini adalah artefak Task 12. Deployment production **belum**
> dijalankan dan **tidak boleh** dijalankan tanpa persetujuan Product Owner.
> Semua contoh di sini menggunakan nama/domain placeholder, bukan nilai production nyata.

---

## 1. Prasyarat Server

| Komponen | Kebutuhan minimum | Catatan |
|---|---|---|
| OS | Linux (Debian/Ubuntu LTS disarankan) | Windows tidak disarankan untuk production |
| Docker Engine | 24+ | |
| Docker Compose | v2.20+ (plugin `docker compose`) | Mendukung `mem_limit`/`cpus`/`pids_limit`, `env_file.required`, `secrets` |
| MariaDB | 11.4+ (external) | Dikelola **terpisah** dari Core; bukan tanggung jawab Core |
| Nginx Proxy Manager | versi terbaru | Reverse proxy publik → Core; TLS/HTTPS di NPM |
| Network | `proxy` (non-internal) dan `tools` (internal) | dibuat sekali di host |
| Resource | ≥ 1 vCPU, ≥ 512 MB RAM untuk Core | Core tidak berat; beban utama di MariaDB & tool |

Core **tidak** menyediakan database, **tidak** mengelola MariaDB, dan **tidak** menjalankan migrasi otomatis saat startup.

---

## 2. Struktur Direktori Deployment

```
/srv/tools-bpbj/
├── Dockerfile            # dari deploy/core/Dockerfile
├── docker-compose.yml    # dari deploy/core/docker-compose.yml
├── core.env              # NON-secret config (dibuat dari core.env.example)
└── secrets/
    ├── db_dsn.txt        # secret: DSN MariaDB (mode 600)
    ├── csrf_secret.txt   # secret: CSRF HMAC key (mode 600)
    └── tool-hmac/        # direktori: <slug>.json per tool (mode 600)
        └── <slug>.json
```

Di repositori, artefak berada di `deploy/core/`:
- `deploy/core/Dockerfile`
- `deploy/core/docker-compose.yml`
- `deploy/core/core.env.example`
- `.dockerignore` (root repo)

---

## 3. Membuat Docker Network

Core bergabung ke **dua** network eksternal:

```bash
# Network publik/shared untuk NPM <-> Core. HARUS non-internal agar Core
# juga dapat menjangkau MariaDB (internal: true memblokir egress).
docker network create proxy

# Network internal khusus Core <-> tool. Gunakan --internal.
docker network create --internal tools
```

**Aturan egress database (penting):** karena `tools` bersifat `internal: true`,
Core menjangkau MariaDB melalui network `proxy` (non-internal) atau network `db`
khusus — **JANGAN** melalui `tools`. MariaDB tidak boleh berada di network `tools`.

---

## 4. Menyiapkan Konfigurasi & Secret

### 4.1 Variabel non-secret (`core.env`)

Salin `core.env.example` menjadi `core.env`, lalu sesuaikan nilai production-nya.
Semua variabel berikut adalah yang **benar-benar dibaca** aplikasi:

| Variabel | Contoh | Keterangan |
|---|---|---|
| `APP_ENV` | `production` | `development` atau `production` |
| `HTTP_ADDR` | `:8080` | Alamat bind internal container |
| `HTTP_READ_HEADER_TIMEOUT_SECONDS` | `10` | Timeout baca header |
| `DB_DSN_FILE` | `/run/secrets/db_dsn` | Path file DSN (prioritas atas `DB_DSN`) |
| `SESSION_TTL` | `12h` | Umur sesi admin |
| `COOKIE_SECURE` | `true` | Wajib `true` di production (HTTPS) |
| `LOGIN_RATE_LIMIT` / `LOGIN_RATE_WINDOW` | `5` / `15m` | Rate limit login admin |
| `CSRF_SECRET_FILE` | `/run/secrets/csrf_secret` | Path file CSRF key |
| `PREAUTH_CSRF_TTL` | `10m` | Umur token CSRF pra-login (maks 10m) |
| `TRUSTED_ORIGIN` | `https://tools.example.go.id` | Domain publik Core (untuk cek Origin) |
| `TRUSTED_PROXIES` | `172.18.0.3` | Daftar IP/CIDR reverse proxy terpercaya (lihat �4.1.1). Kosong = tidak mempercayai proxy mana pun |
| `UPSTREAM_ALLOWED_HOSTS` | `image-compressor,pdf-tool` | **Allowlist hostname** tool (default-deny) |
| `UPSTREAM_ALLOWED_CIDRS` | `172.16.0.0/12` | Allowlist CIDR IP upstream (default sesuai desain Phase 0) |
| `GATEWAY_MAX_BODY_BYTES` | `26214400` | Batas ukuran body (25 MiB) |
| `GATEWAY_CONNECT_TIMEOUT` | `5s` | Timeout koneksi upstream |
| `GATEWAY_RESPONSE_HEADER_TIMEOUT` | `60s` | Timeout header respons |
| `GATEWAY_IDLE_CONN_TIMEOUT` | `90s` | Idle koneksi |
| `TOOL_HMAC_KEYS_DIR` | `/run/secrets/tool-hmac` | **WAJIB di production** (lihat fail-fast §4.3) |
| `HMAC_SKEW` | `60s` | Toleransi selisih waktu tanda tangan |
| `NONCE_TTL` | `2m` | TTL nonce replay (harus ≥ 2× `HMAC_SKEW`) |
| `GATEWAY_SIGN_BUFFER_BYTES` | `1048576` | Buffer body untuk penandatanganan (1 MiB) |
| `TOKEN_DEFAULT_TTL` | `720h` | TTL default access token (30 hari) |
| `TOKEN_MAX_TTL` | `8760h` | TTL maksimum token (365 hari) |
| `TOKEN_RATE_LIMIT` / `TOKEN_RATE_WINDOW` | `60` / `1m` | Rate limit validasi token |
| `HEALTHCHECK_INTERVAL` | `30s` | Interval health check (`0` = menonaktifkan poller) |
| `HEALTHCHECK_TIMEOUT` | `5s` | Timeout tiap health check |
| `HEALTHCHECK_MAX_CONCURRENT` | `5` | Maksimum health check bersamaan |
| `ACTIVITY_METADATA_LIMIT` | `2048` | Batas ukuran metadata activity log |

#### 4.1.1 Resolusi Client IP & Trusted Proxy (`TRUSTED_PROXIES`)

Core berjalan di belakang Nginx Proxy Manager (NPM). Tanpa konfigurasi khusus,
koneksi yang diterima Core berasal dari IP container NPM (mis. `172.18.0.3`),
sehingga rate limit login, throttling token, dan log audit akan mencatat IP NPM
untuk **semua** pengunjung. Untuk memperbaiki ini, set `TRUSTED_PROXIES` ke
daftar **spesifik** IP/CIDR reverse proxy yang memang berada di jalur trafik:

```
TRUSTED_PROXIES=172.18.0.3
```

Mekanisme keamanan:

- **Default aman:** bila `TRUSTED_PROXIES` kosong, Core hanya memakai alamat TCP
  peer (`RemoteAddr`) dan **mengabaikan** seluruh header `X-Forwarded-For`. Ini
  berarti klien yang terhubung langsung tidak dapat memalsukan alamatnya.
- **Header forwarded hanya dipercaya dari proxy terdaftar:** `X-Forwarded-For`
  dibaca **hanya** jika koneksi benar-benar berasal dari salah satu IP/CIDR di
  `TRUSTED_PROXIES`. Untuk koneksi langsung dari IP lain, header diabaikan.
- **Anti-spoofing multi-hop:** rantai `X-Forwarded-For` ditelusuri dari kanan ke
  kiri, melewati hop yang terpercaya, dan berhenti pada hop pertama yang tidak
  terpercaya (klien sebenarnya). Klien tidak bisa "menyelipkan" hop palsu di
  sisi kiri untuk mengelabui limiter.
- **Konsisten di semua titik:** hasil resolusi yang sama dipakai untuk rate limit
  login (`/admin/login`), throttling validasi token di gateway, header
  `X-Forwarded-For` yang diteruskan ke tool, serta metadata log aktivitas (login,
  tool, token).

**Penting — jangan** mempercayai seluruh subnet Docker (mis.
`172.18.0.0/16`) kecuali memang setiap anggota subnet tersebut terpercaya.
Cukup daftarkan IP container NPM. Bila NPM di-restart dan IP container-nya
berubah, perbarui `TRUSTED_PROXIES` (atau beri NPM IP statis di network `proxy`).
Nilai IP (`172.18.0.3`) di sini hanya contoh; verifikasi dengan
`docker network inspect proxy` di server.

### 4.2 Secret (file)

Buat file secret dengan izin ketat (mode `600`, owner user deployment). **Jangan**
commit secret ke Git; `core.env` dan direktori `secrets/` sudah di-ignore.

```bash
install -d -m 700 secrets
chmod 700 secrets

# DSN MariaDB (satu baris, tanpa newline ekstra)
printf '%s' 'app_user:STRONG_PASSWORD@tcp(db-host:3306)/mycoreplat?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci&loc=UTC&timeout=5s' > secrets/db_dsn.txt
chmod 600 secrets/db_dsn.txt

# CSRF HMAC key (minimal 32 byte acak)
openssl rand -base64 32 > secrets/csrf_secret.txt
chmod 600 secrets/csrf_secret.txt

# Per-tool HMAC keys: satu file JSON per tool
install -d -m 700 secrets/tool-hmac
cat > secrets/tool-hmac/image-compressor.json <<'JSON'
{
  "toolSlug": "image-compressor",
  "keys": [
    { "keyId": "k-2026-11", "secret": "<base64 32 byte>", "status": "active" }
  ]
}
JSON
chmod 600 secrets/tool-hmac/*.json
```

**JANGAN** membuat password/secret contoh (dummy) yang benar-benar dipakai. Nilai
placeholder di dokumen ini hanya ilustrasi.

### 4.3 Fail-fast (perilaku wajib)

Core **berhenti dengan pesan jelas** bila konfigurasi production tidak lengkap:

- `TOOL_HMAC_KEYS_DIR` kosong saat `APP_ENV=production` → error
  `TOOL_HMAC_KEYS_DIR must be set in production: tools reject unsigned requests`.
- DSN tidak diset (baik `DB_DSN_FILE` maupun `DB_DSN`) →
  `database DSN is not configured: set DB_DSN_FILE or DB_DSN`.
- CSRF secret tidak diset → error serupa.
- `NONCE_TTL` < 2×`HMAC_SKEW`, `TOKEN_MAX_TTL` < `TOKEN_DEFAULT_TTL`, atau nilai
  numerik/durasi tidak valid → error saat startup.

Kegagalan terjadi **sebelum** server menerima trafik (fail-fast), tidak ada nilai default yang tidak aman.

---

## 5. Build Image

Dari root repositori (konteks build harus root karena `go.mod`):

```bash
docker build -f deploy/core/Dockerfile -t tools-bpbj/core:1.0.0 .
```

- Multi-stage: builder `golang:1.27-bookworm` → runtime `gcr.io/distroless/static-debian12:nonroot`.
- Runtime **tanpa** shell, **tanpa** compiler, **tanpa** curl/wget; berjalan sebagai
  uid 65532 (non-root); CA cert sudah tersedia.
- `ENTRYPOINT ["/app/core"]` (exec form) → sinyal SIGTERM sampai ke proses → graceful shutdown.
- Image **tidak** memuat `.env`, secret, atau kredensial.

Verifikasi cepat:

```bash
docker inspect tools-bpbj/core:1.0.0 --format 'User={{.Config.User}} Entrypoint={{.Config.Entrypoint}}'
# User=65532 Entrypoint=[/app/core]
```

---

## 6. Start / Stop / Restart

```bash
cd /srv/tools-bpbj

# Start (detached)
docker compose up -d

# Lihat status + health
docker compose ps

# Lihat log
docker compose logs -f core

# Restart
docker compose restart core

# Stop (container hilang, data tidak terpengaruh)
docker compose down
```

Compose **tidak** mem-publish port ke host. Untuk smoke test lokal saja:

```bash
docker run --rm -p 127.0.0.1:19090:8080 --env-file core.env tools-bpbj/core:1.0.0
```

---

## 7. Health Check

- Endpoint liveness: **`GET /health`** (tanpa autentikasi) → `{"status":"ok","service":"core"}`.
- Healthcheck container memakai probe bawaan binary:
  `test: ["CMD", "/app/core", "-healthcheck"]` (interval 30s, timeout 5s, retries 3,
  start_period 20s). Probe hanya membaca `HTTP_ADDR` dan memanggil `/health`;
  **tidak** mencetak konfigurasi atau secret.
- Halaman admin `GET /admin/health` (di balik `RequireAuth`) menampilkan status
  kesehatan setiap tool, waktu pemeriksaan terakhir, latency, dan alasan singkat
  yang **aman** (tanpa alamat/port internal).

---

## 8. Konfigurasi Nginx Proxy Manager

Core berada di network `proxy`. Buat **Proxy Host** di NPM:

| Setelan | Nilai |
|---|---|
| Domain Names | `tools.example.go.id` |
| Scheme | `http` (NPM → Core, TLS diterminasi NPM) |
| Forward Hostname / IP | `mycoreplat-core` (nama container) atau IP container di network `proxy` |
| Forward Port | `8080` |
| Block Common Exploits | aktif |
| Websockets Support | aktif (untuk HTMX/streaming) |
| SSL | Let's Encrypt, Force SSL, HTTP/2 |

Cabang route yang perlu diteruskan: `/`, `/admin/*`, `/t/*` (gateway tool), `/health`.

**JANGAN** mengubah DNS atau konfigurasi NPM production tanpa persetujuan Product Owner.

---

## 9. Migrasi Database (Manual)

Migrasi **tidak** dijalankan oleh aplikasi (tidak ada AutoMigrate). Gunakan binary
`golang-migrate` dengan DSN aplikasi:

```bash
export MIGRATE_DSN="mysql://app_user:PASSWORD@tcp(db-host:3306)/mycoreplat?multiStatements=true&parseTime=true"

# Cek versi
migrate -path migrations -database "$MIGRATE_DSN" version

# Naik ke versi terbaru
migrate -path migrations -database "$MIGRATE_DSN" up

# Turun satu langkah (rollback)
migrate -path migrations -database "$MIGRATE_DSN" down 1
```

Catatan:
- `multiStatements=true` wajib (file `up` berisi beberapa `CREATE TABLE`).
- Migrasi memakai user aplikasi yang punya hak DDL pada schema `mycoreplat`, atau
  user migrasi khusus dengan hak lebih terbatas.
- **Jangan** menjalankan migrasi production tanpa persetujuan PO.

---

## 10. Backup & Restore

**Backup** (dump logis):

```bash
docker exec -i <mariadb-container> mariadb-dump \
  --single-transaction --routines --triggers \
  -u app_user -p"$DB_PASSWORD" mycoreplat > backup-mycoreplat-$(date +%F).sql
```

**Restore** ke instance baru:

```bash
docker exec -i <mariadb-container> mariadb -u app_user -p"$DB_PASSWORD" mycoreplat < backup-mycoreplat-YYYY-MM-DD.sql
```

Praktik:
- Backup sebelum setiap migrasi/upgrade.
- Simpan di luar host aplikasi; enkripsi backup bila memuat data.
- Uji restore berkala pada DB staging.

---

## 11. Pembaruan Aplikasi (Update)

```bash
cd /srv/tools-bpbj

# 1. Backup DB (lihat §10)
# 2. Pull image baru / build ulang
docker compose build          # atau: docker compose pull core
# 3. Terapkan migrasi baru (lihat §9)
# 4. Recreate container
docker compose up -d
# 5. Verifikasi
docker compose ps
curl -fsS http://127.0.0.1:8080/health   # (dari dalam container / host yang punya akses)
```

Compose memakai `restart: unless-stopped`, jadi Core otomatis menyala kembali setelah reboot host.

---

## 12. Troubleshooting

| Gejala | Kemungkinan penyebab | Tindakan |
|---|---|---|
| Core exit saat start, log `fatal: ...` | Konfigurasi/secret tidak lengkap | Baca pesan; lengkapi `core.env`/secret. Lihat §4.3 |
| `database DSN is not configured` | `db_dsn.txt` belum ada / `DB_DSN_FILE` salah | Periksa mount secret & isi file |
| Healthcheck `unhealthy` | `/health` tidak merespons | Cek log; pastikan `HTTP_ADDR` benar; pastikan probe `-healthcheck` ada di image |
| NPM 502 | Core tidak di network `proxy` / nama host salah | Cek `docker network inspect proxy`; pastikan `container_name` cocok |
| Tool 502 di `/t/...` | Upstream tidak di allowlist / tidak aktif | Cek `UPSTREAM_ALLOWED_HOSTS`, status tool, dan `GET /admin/health` |
| Tool 401 di `/t/...` | Tool `access=token` tanpa token valid | Kirim `Authorization: Bearer <token>` |
| Tool 429 | Rate limit validasi token | Tunggu; periksa `TOKEN_RATE_LIMIT`/`TOKEN_RATE_WINDOW` |
| Migrasi gagal | DDL/urutan FK, hak user | Periksa pesan; pastikan `multiStatements=true`; cek versi dirty (`migrate ... version`) |

---

## 13. Prosedur Recovery (Jika Deployment Gagal)

1. **Jangan panik hapus volume.** Data ada di MariaDB eksternal, bukan di container Core.
2. Hentikan container bermasalah tanpa menghapus volume:
   `docker compose stop core`
3. Rollback image ke tag sebelumnya:
   edit `CORE_VERSION` (atau `image:`) ke tag stabil terakhir, lalu `docker compose up -d`.
4. Rollback migrasi bila upgrade DB bermasalah: `migrate -database "$MIGRATE_DSN" down 1`
   (hanya jika aman; koordinasi dengan PO).
5. Jika konfigurasi rusak, pulihkan `core.env` dan `secrets/` dari salinan aman (mode 600).
6. Verifikasi: `docker compose ps` (healthy), `GET /health` mengembalikan `{"status":"ok"}`.
7. Setelah pulih, catat kejadian dan perbaiki akar masalah sebelum mencoba lagi.

---

## 14. Batas Tanggung Jawab Core vs Layanan Eksternal

| Aspek | Core (aplikasi ini) | Eksternal (di luar Core) |
|---|---|---|
| Database | Mengakses DB via DSN; **tidak** membuat/mengelola MariaDB | Penyediaan, backup, replikasi, patch MariaDB |
| Migrasi schema | Menyediakan file migrasi di `migrations/` | Eksekusi `golang-migrate`, kontrol versi schema |
| TLS / sertifikat | Tidak menangani TLS | Nginx Proxy Manager (terminasi TLS, Let's Encrypt) |
| DNS | Tidak menyentuh DNS | Tim infra/DNS |
| Docker socket | **Tidak pernah** di-mount ke Core | Host Docker |
| Jaringan | Bergabung ke `proxy` + `tools` | Pembuatan network, firewall host |
| Tool runtime | Gateway + otorisasi + proxy ke tool | Container tool terpisah (masing-masing punya Dockerfile) |
| Secret | Membaca secret dari file/env | Penyediaan & rotasi secret oleh operator |

---

## 15. Catatan Keamanan Artefak

- Compose **tidak** mem-publish port Core; hanya `expose: 8080` (internal).
- **Tidak** ada mount Docker socket; **tidak** ada `privileged: true`.
- Container: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, `tmpfs: [/tmp]`.
- Limit resource versi Compose standalone: `mem_limit: 512m`, `cpus: 1.0`, `pids_limit: 256`.
- Image runtime non-root (uid 65532), tanpa shell/compiler.
- Secret tidak masuk Git (`.gitignore`) maupun image (`.dockerignore`, diverifikasi ulang).
- Migrasi dijalankan eksplisit (tidak ada AutoMigrate).
- Kebijakan SSRF/CIDR Task 9 tidak diubah; health check memakai transport pinned-IP yang sama.
