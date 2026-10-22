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
--
-- Rolling deploy: the column is added NOT NULL with a default, so an older
-- API pod that still inserts without expires_at during the rollout writes a
-- token that expires in 90 days instead of failing. The current code always
-- sets the value. The table holds a handful of rows per organization, so the
-- rewrite a volatile default causes is instant.

ALTER TABLE scim_tokens
    ADD COLUMN IF NOT EXISTS expires_at timestamptz NOT NULL DEFAULT (now() + interval '90 days');

COMMENT ON COLUMN scim_tokens.expires_at IS
    'The token stops authenticating at this time (1 to 365 days after creation; a rotation brings it to at most 24 hours ahead).';
