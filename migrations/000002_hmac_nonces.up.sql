-- 000002_hmac_nonces
-- Shared replay-protection store for Core -> Tool HMAC request signing.
--
-- Why a table: nonce replay protection MUST be atomic and MUST NOT rely on a
-- process-local cache as the final mechanism (docs/architecture.md §4.4.1,
-- docs/security-design.md §11.1). A UNIQUE primary key on (key_id, nonce)
-- makes "check and store" a single atomic INSERT: the first writer wins and
-- every concurrent duplicate fails with a duplicate-key error, so exactly one
-- replay is admitted.
--
-- Rows are given a TTL (expires_at >= accepted skew window) and pruned by the
-- Core janitor or the owning tool. Nothing sensitive is stored here: a nonce
-- is a public random value that already travelled in a request header.

CREATE TABLE hmac_nonces (
    key_id     VARCHAR(64)  NOT NULL,
    nonce      VARCHAR(128) NOT NULL,
    expires_at DATETIME(3)  NOT NULL,
    created_at DATETIME(3)  NOT NULL,
    PRIMARY KEY (key_id, nonce),
    KEY idx_hmac_nonces_expires_at (expires_at)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;
