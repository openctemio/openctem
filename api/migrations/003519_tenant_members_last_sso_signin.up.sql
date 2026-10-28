-- The last time this member, as an owner or admin, signed in through the
-- organization's own identity provider. Requiring SSO needs one such sign-in
-- first, so an organization cannot enforce SSO before its IdP path is proven.
-- Nullable, no backfill: nothing is rewritten on a populated table.
ALTER TABLE tenant_members ADD COLUMN IF NOT EXISTS last_sso_signin_at timestamptz;
