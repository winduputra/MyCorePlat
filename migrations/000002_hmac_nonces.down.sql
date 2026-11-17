-- 000002_hmac_nonces (rollback)
-- Drops the shared replay-protection store. Safe to revert: it holds only
-- short-lived, non-sensitive nonce records.

DROP TABLE IF EXISTS hmac_nonces;
