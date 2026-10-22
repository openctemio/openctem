-- SCIM tokens expire (docs/architecture/scim-provisioning.md, "Token
-- lifetime and rotation").
--
-- A SCIM token can create, suspend and re-role every member of its
-- organization, and until now it never expired. Every token now has an
-- expiry: new tokens take 1 to 365 days at creation.
--
-- Existing tokens get a 90-day grace period from this migration instead of
-- stopping at once: identity providers keep provisioning while an owner
-- rotates the token (POST /api/v1/scim-tokens/{id}/rotate) or mints a new
-- one. Revoked tokens get the same value; they never authenticate anyway.
-- The table holds a handful of rows per organization: the backfill and the
-- NOT NULL check are instant on a populated database.

ALTER TABLE scim_tokens ADD COLUMN IF NOT EXISTS expires_at timestamptz;

UPDATE scim_tokens SET expires_at = now() + interval '90 days' WHERE expires_at IS NULL;

ALTER TABLE scim_tokens ALTER COLUMN expires_at SET NOT NULL;

COMMENT ON COLUMN scim_tokens.expires_at IS
    'The token stops authenticating at this time (1 to 365 days after creation; a rotation brings it to at most 24 hours ahead).';
