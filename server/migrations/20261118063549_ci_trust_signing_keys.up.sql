-- A CI trust configuration can carry the provider's public signing keys,
-- pasted by an administrator, and verify job tokens with them instead of
-- fetching keys from the provider (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
-- "Pasted signing keys"). Adding columns with constant defaults does not
-- rewrite the table; existing trusts keep fetching.

-- Where the keys come from: 'fetch' (the issuer's discovery document and
-- JWKS) or 'pasted' (signing_keys only, never a fetch).
ALTER TABLE ci_trust_configs ADD COLUMN IF NOT EXISTS key_source VARCHAR(16) NOT NULL DEFAULT 'fetch';
ALTER TABLE ci_trust_configs DROP CONSTRAINT IF EXISTS chk_ci_trust_configs_key_source;
ALTER TABLE ci_trust_configs ADD CONSTRAINT chk_ci_trust_configs_key_source
    CHECK (key_source IN ('fetch', 'pasted'));

-- The JWKS document as pasted (public keys, at most 64 KiB; validated by the
-- API: 1 to 10 RSA or P-256 keys, no private material, unique kids).
ALTER TABLE ci_trust_configs ADD COLUMN IF NOT EXISTS signing_keys TEXT;
ALTER TABLE ci_trust_configs DROP CONSTRAINT IF EXISTS chk_ci_trust_configs_signing_keys_size;
ALTER TABLE ci_trust_configs ADD CONSTRAINT chk_ci_trust_configs_signing_keys_size
    CHECK (signing_keys IS NULL OR octet_length(signing_keys) <= 65536);
-- Pasted mode always has keys to verify with.
ALTER TABLE ci_trust_configs DROP CONSTRAINT IF EXISTS chk_ci_trust_configs_pasted_has_keys;
ALTER TABLE ci_trust_configs ADD CONSTRAINT chk_ci_trust_configs_pasted_has_keys
    CHECK (key_source <> 'pasted' OR signing_keys IS NOT NULL);

-- When the keys were last pasted, and the kid that verified the last
-- admitted token (shown on the trust so a rotation is noticed).
ALTER TABLE ci_trust_configs ADD COLUMN IF NOT EXISTS signing_keys_updated_at TIMESTAMPTZ;
ALTER TABLE ci_trust_configs ADD COLUMN IF NOT EXISTS last_key_id VARCHAR(200);
