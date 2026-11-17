# Tools BPBJ — Security Design

Security is a core requirement, not an enhancement. This document specifies how the platform implements authentication, session management, token authorization, server-side enforcement, input/upload handling, and network isolation — plus identified risks and mitigations.

## 1. Threat Model (Summary)

| Asset | Threat | Impact |
|-------|--------|--------|
| Admin credentials | Brute force, credential stuffing | Full control of portal |
| Admin sessions | Session hijacking, CSRF, fixation | Admin impersonation |
| Access tokens | Theft, replay, leakage via URL/logs | Unauthorized tool use |
| Tool services | Direct public exposure, lateral movement | Data exposure, abuse |
| Uploaded files | Malware, resource exhaustion, PII leakage | Host/resource compromise |
| Audit logs | Tampering, secret leakage | Loss of accountability |

**Trust boundaries:** the browser (untrusted), Nginx Proxy Manager edge, Core (trusted gateway), internal tool network (semi-trusted — tools verify Core's HMAC signature, §11.1), MariaDB (trusted, external).

## 2. Administrator Password Hashing

- **Algorithm:** Argon2id (preferred) or bcrypt as fallback.
- Argon2id parameters tuned to environment (memory ≥ 64 MB, iterations ≥ 3, parallelism per cores) — documented in config, not hardcoded.
- Only the **password hash** is stored (`admins.password_hash`); plaintext is never persisted or logged.
- Password policy: minimum length + complexity; reject weak/known-breached passwords (best-effort).
- **Constant-time comparison** for hash verification.

## 3. Secure Session Management

- **Server-side sessions** (`admin_sessions`): only a **hash** of the session token is stored.
- **Cookie flags:** `HttpOnly`, `Secure` (HTTPS only), `SameSite=Lax` (or `Strict` where feasible), narrow `Path`, no `Domain` broadening.
- **Expiry:** absolute lifetime + idle timeout; enforced server-side against `expires_at`.
- **Rotation:** regenerate session ID on login and privilege changes to prevent fixation.
- **Revocation:** explicit `revoked_at` on logout and on forced logout; logout invalidates the server-side row.
- **Lookup rules:** reject sessions where `revoked_at IS NOT NULL` or `expires_at <= now`.
- **Anomaly signals:** record `ip_address` / `user_agent`; surface changes for admin awareness.

## 4. CSRF Protection

- **Per-session CSRF token** stored with the session (`admin_sessions.csrf_token`), embedded in admin forms.
- **Double-submit + server verification**: token must match the session's token, validated server-side on every state-changing request (POST/PUT/PATCH/DELETE).
- **SameSite cookies** as defense-in-depth.
- HTMX requests include the CSRF token via a header (`X-CSRF-Token`); Core validates it identically.
- Reject state-changing requests lacking a valid token (403).

## 5. Login Rate Limiting

- **Per-IP and per-account** rate limiting on the login endpoint (e.g. sliding window: N attempts per M minutes).
- **Progressive backoff / temporary lockout** after repeated failures.
- Responses are **generic** (do not reveal whether the username exists).
- **Audit** failed and successful logins in `activity_logs`.
- Consider CAPTCHA/backoff escalation only if abuse persists (future).

## 6. Token Hashing, Expiration & Revocation

- **Format:** every token is `tbpbj_<8-char prefix>_<43-char base64 secret>` (recognizable prefix + 32 bytes / 256 bits of entropy in the secret half).
- **Storage:** only `access_tokens.token_hash` (SHA-256 hex of the plaintext) is stored; **plaintext is shown exactly once** at generation and never re-readable. The plaintext is never logged.
- **Prefix:** `token_prefix` is stored for admin identification without revealing the secret.
- **One token = one tool**: enforced by `access_tokens.tool_id`; a token is only valid for the tool it was issued for.
- **Expiration is mandatory:** every access token MUST have a non-NULL `expires_at`. Tokens **cannot be created without an expiry** (no "never expires" tokens); if a create request omits an expiry, the configured `TOKEN_DEFAULT_TTL` applies, capped by `TOKEN_MAX_TTL`. Validation always rejects a token whose `expires_at <= now`.
- **Revocation:** `revoked_at`; revoking a token invalidates access immediately. The admin revoke endpoint is scoped to the token's own tool (a cross-tool revoke mutates nothing and returns not-found).
- **Submission:** the token is presented **only** via the `Authorization: Bearer <token>` header at the gateway. Tokens are **never** accepted from a query string or path segment, and the plaintext is never put in a URL.
- **Generic rejection:** any invalid token (unknown, expired, revoked, wrong tool, or malformed) returns the same generic `401`, so the failure reason is not disclosed.
- **Rate limited:** token validation is throttled per source IP; requests over the limit get `429` before any hashing or lookup.
- **Honest UI:** the recipient label is descriptive only; the platform explicitly states that anyone with a valid token can use it.
- **Note on sessions:** the `tool_access_sessions` table exists in the schema but is **not used** by the current implementation. Today the gateway authorizes each request directly against the token (hash + expiry + revocation + tool binding); no per-token session row is created. The "sessions bounded by token" rule therefore applies if/when that table is adopted.

## 7. Per-Tool Authorization & Server-Side Status Enforcement

Enforced **on every proxied request**, in order:

1. Resolve tool by `slug` from DB. Missing → `404`.
2. Enforce **status**: `disabled` → `403`; `maintenance` → maintenance page (`503`); `draft` → not publicly reachable.
3. Enforce **access type**:
   - `public`: allow.
   - `token`: require a valid token presented as `Authorization: Bearer <token>`; the token must match this tool (`tool_id`), be unexpired and unrevoked; otherwise a generic `401`. (See §6 — the current implementation authorizes directly against the token rather than a `tool_access_sessions` row.)
4. Only then proxy to `upstream_url`.

- **Never** rely on frontend visibility or JavaScript checks — all decisions are server-side.
- Status/access changes take effect immediately (DB-driven), no redeploy.

## 8. Input Validation & Error Handling

- Validate **all** user input server-side (path params, query, form, JSON, headers).
- Slug/IDs validated against patterns; upstream URLs restricted to internal hosts.
- Parameterized queries via GORM (no string-concatenated SQL).
- **Generic error responses** to clients; detailed errors only in server logs.
- Never expose secrets, stack traces, or internal addresses to the browser.

## 9. Upload Limits & Temporary File Cleanup

- **Upload size limits** enforced at the gateway (Core) and optionally per-tool (lower).
- Prefer **streaming** to tools; avoid unnecessary buffering of large files at Core.
- **Temporary files:** any temp files (Core or tool) are created in a dedicated, non-executable temp dir and **cleaned up** after processing; scheduled sweeper for orphans.
- Content-type/extension checks where applicable; treat uploaded content as untrusted.
- Reject oversized or malformed uploads early (413/400).

## 10. Secrets & Configuration

- Secrets are supplied via **environment variables or secret files**, never hardcoded or committed. The secrets the app actually reads:
  - **DB DSN** — `DB_DSN_FILE` (preferred) or `DB_DSN`.
  - **CSRF key** (login pre-auth HMAC) — `CSRF_SECRET_FILE` (preferred) or `CSRF_SECRET`.
  - **Per-tool HMAC keys** — `TOOL_HMAC_KEYS_DIR` (one `<slug>.json` per tool; required in production).
- No secrets in logs, errors, or browser responses.
- `.env` / secret files excluded from version control (`.gitignore`: `secrets/`, `**/secrets/`, `deploy/core/core.env`).
- Non-secret tuning (session TTL, cookie flags, rate limits, gateway timeouts, `UPSTREAM_ALLOWED_HOSTS`, `UPSTREAM_ALLOWED_CIDRS`, `HMAC_SKEW`, `NONCE_TTL`, token TTLs, health-check bounds) is documented in `core.env.example` and `.env.example`; see `docs/deployment-guide.md` for the authoritative list.

## 11. Container & Network Isolation

- **Mounted Docker socket:** NOT mounted into Core.
- **Non-root containers** wherever possible (`USER` non-root, high UID).
- **Internal networks:** tools live on an internal-only Docker network; no published host ports.
- **Edge exposure:** only Nginx Proxy Manager is public; it proxies to Core on the `proxy` network.
- **Resource limits:** CPU/memory limits and health checks on all containers.
- **Egress restriction** where practical (tools should not need broad outbound internet).
- **Tools authenticate Core cryptographically:** network isolation is **not** treated as identity. Every Core→tool request is HMAC-signed and verified by the tool (see §11.1); the `X-Gateway` marker alone is never trusted.

### 11.1 Internal Service-to-Service Authentication (Core → Tool)

A private Docker network is defense-in-depth, **not proof of identity** — a compromised or misconfigured container on the same network could impersonate Core. Therefore:

- Core signs every forwarded request with **HMAC-SHA256** over a canonical string (method, path, query, keyId, timestamp, nonce, body hash), sent via `X-Signature`, `X-Signature-Key-Id`, `X-Signature-Timestamp`, `X-Signature-Nonce`.
- **Per-tool secret (no global shared secret):** each tool has its own distinct HMAC secret; compromise of one tool's secret cannot forge Core's signature to any other tool. The signing key is identified by `X-Signature-Key-Id`.
- **Rotation with zero downtime:** a tool may hold two secrets (current + next). Rotation = deliver new key to tool (accept both) → switch Core to new key → after the transition window revoke the old key. Either key verifies during the window, so rotation causes no downtime; the window is bounded and configurable.
- The tool **verifies** the signature (constant-time compare), rejects requests with invalid/missing signatures or unknown/revoked `keyId` (`401`), and rejects timestamps outside a **±60s** skew window.
- **Mandatory replay protection (atomic):** a nonce cache keyed by `keyId`+nonce with TTL ≥ the skew window (e.g. ≥120s) rejects any reused nonce. The **check-and-store must be atomic** (insert-if-absent / compare-and-set / single atomic operation): concurrent requests carrying the same `keyId`+nonce must resolve to exactly one accepted and the rest rejected. A non-atomic "check then insert" would let two concurrent replays both pass; use an atomic primitive (e.g. `SETNX`/`SET NX PX` in shared stores, or a locking/atomic map op in-process). A repeated nonce within TTL is `401`. The cache is bounded in size to avoid becoming a DoS vector.
- Per-tool secrets are provisioned via **secret file/env**, are **rotatable**, and are **distinct** from admin-session and user-token secrets.
- Internal signature headers are stripped from responses (never leaked to the browser).
- A tool that does not verify the signature is **non-compliant** with the integration contract.
- **Future:** mTLS may replace/augment HMAC; not required in the current phase.

### 11.2 Upstream URL Validation (SSRF Prevention)

Because `upstream_url` originates from a manifest/Admin input, Core validates it **on save and before each connection**:

- Allow only `http`/`https`; reject `file://`, `gopher://`, etc.
- Allow only Docker service hostnames or allowlisted internal IP ranges (RFC1918 / internal DNS); reject public hosts, `localhost`/`127.0.0.0/8`/`::1`, link-local `169.254.0.0/16` (cloud metadata), and userinfo/traversal forms.
- Restrict ports to an allowlisted set.
- **Connect-to-validated-IP (DNS rebinding):** a resolve-and-check *before* connecting is insufficient (TOCTOU rebind). Core **MUST** dial the **exact IP it validated** (pin the resolved IP), preserving `Host`/SNI, so no unvalidated second lookup occurs between check and connect.
- Block upstream redirects to non-allowlisted hosts; redirect targets are re-validated with the same pinned-IP rule.
- Restrict Core egress to the internal tool network where practical.
- Violations are rejected with a clear error and recorded in `activity_logs`.

### 11.3 Health-Check Load Limits

Health polling is bounded so it cannot overload Core or tools: interval **30s**, per-check timeout **5s**, bounded concurrency (e.g. **5** simultaneous checks), retries **0–1**, no overlapping sweeps, and batched DB writes. Health checks are HMAC-signed and never carry a body to log. See `architecture.md` §4.6.

## 12. Audit Logging

- Append-only `activity_logs`. The implementation records these **action** values:

  | Action | Written when |
  |--------|--------------|
  | `admin.login` | Successful admin login |
  | `admin.login_failed` | Failed admin login (attempted username is **not** logged) |
  | `admin.logout` | Admin logout |
  | `tool.create` | Tool created |
  | `tool.update` | Tool updated |
  | `tool.delete` | Tool deleted |
  | `token.create` | Access token created (metadata: slug, prefix, label, expiry — never plaintext/hash) |
  | `token.revoke` | Access token revoked |
  | `health.check_failed` | A tool's health transitioned to unhealthy |
  | `health.check_recovered` | A tool's health transitioned back to healthy |

  (`tool.access_changed` and `tool.status_changed` are defined constants available for future use; status/access edits are currently recorded through `tool.update`.)
- **Strict deny-list — `activity_logs` and application logs MUST NEVER contain:**
  - access tokens or token plaintext,
  - session IDs / session cookies,
  - passwords or password hashes,
  - `Authorization` headers or any `X-Signature*` internal auth values,
  - request/response bodies or uploaded file contents.
- Captured metadata is **sanitized**: keys containing password/secret/token/hash/cookie/csrf/authorization/signature/dsn/session/credential/private-key are dropped; values are length-bounded; the encoded document is capped at `ACTIVITY_METADATA_LIMIT` bytes and replaced with a small truncation marker if it would exceed the cap.
- A failed activity write **never** breaks or alters the security response of the request it was recording; failures are swallowed (and not recursively logged).
- Retention policy documented; logs support incident review.

### 12.1 Health-Check Reasons (safe error strings)

`tool_health_checks.error_message` stores only a **fixed reason code** (never raw transport text, which could echo hostnames/IPs/ports):

`timeout`, `connection failed`, `tls handshake failed`, `upstream address not allowed`, `unexpected status code`, `response body too large`, `request failed`.

## 13. Risk Register & Mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|-----------|
| R1 | Admin login brute force | Med | High | Rate limit + backoff + generic errors + audit |
| R2 | Session hijacking | Low | High | HttpOnly/Secure/SameSite, server-side sessions, rotation, short TTL |
| R3 | CSRF on admin forms | Med | High | Per-session CSRF token, SameSite, server validation |
| R4 | Access token theft/replay | Med | High | Hash-only storage, no tokens in URLs, **mandatory expiry (expires_at NOT NULL)**, revocation, HTTPS |
| R5 | Token shared beyond recipient | High | Med | Documented honestly; mandatory expiry + revocation + per-tool scoping; audit |
| R6 | Tool directly exposed publicly | Med | High | Internal-only network, no published ports, NPM only to Core |
| R7 | Tool container compromised → lateral movement | Low | High | Network isolation, non-root, resource limits, egress restriction |
| R8 | Oversized/malicious uploads | Med | Med | Size limits, streaming, temp cleanup, content checks |
| R9 | Secrets leaked via logs/code | Low | High | Env/secret files, no logging of secrets, `.gitignore` |
| R10 | SQL injection | Low | High | GORM parameterized queries, input validation |
| R11 | Audit log tampering / growth | Low | Med | Append-only, retention/pruning policy, restricted DB grants |
| R12 | Upstream dead/misbehaving tool | Med | Low | Timeouts, 502/504 handling, health checks, maintenance mode |
| R13 | Session outliving token expiry | Med | High | Bound session expiry to token; re-validate token at request time |
| R14 | Weak/leaked admin password | Med | High | Argon2id, password policy, breach checks |
| R15 | Spoofed Core on internal network (no crypto identity) | Med | High | **Per-tool** HMAC-signed core→tool requests, keyId + timestamp + mandatory nonce cache, tool-side verification (§11.1) |
| R16 | SSRF via malicious/misconfigured upstream URL | Med | High | Upstream allowlist, scheme/host/port checks, **connect-to-validated-IP** (no TOCTOU rebind), redirect block (§11.2) |
| R17 | Secret leakage in activity logs / app logs | Med | High | Strict deny-list (tokens, cookies, passwords, auth headers, bodies) (§12) |
| R18 | Health-check storms overloading Core/tools | Med | Med | Bounded interval/timeout/concurrency, no overlapping sweeps (§11.3) |
| R19 | Internal secret leaked/not rotated | Low | High | **Per-tool** secrets, secret file/env only, distinct from other secrets, dual-key rotation window (§11.1) |
| R20 | Replay of a captured signed request within skew window | Low | High | **Mandatory** nonce cache keyed by keyId+nonce, TTL ≥ skew window, bounded size (§11.1) |
| R21 | Concurrent replay passing a non-atomic nonce check | Low | High | **Atomic** check-and-store (insert-if-absent/CAS) so concurrent duplicates admit exactly one (§11.1) |

## 14. Security Testing Requirements (Phase 1+)

- Unit tests for authorization decisions (status × access-type matrix).
- Session/CSRF validation tests.
- Token hashing/expiry/revocation tests.
- Regression guards for server-side enforcement (no client-trust paths).
- Static analysis (`go vet`, `golangci-lint`) in CI.

## 15. Open Security Questions

- Exact Argon2id parameters for the target host.
- Idle-timeout vs absolute-timeout values for admin sessions.
- Whether to add per-token IP allowlisting (deferred to avoid over-engineering).
- Retention window for `activity_logs` and `tool_health_checks`.
