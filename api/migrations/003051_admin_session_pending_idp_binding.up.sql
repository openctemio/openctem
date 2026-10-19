-- Console IdP binding needs the administrator's own second factor
-- (docs/architecture/platform-console.md, "Identity provider binding").
-- The first IdP sign-in of an unbound administrator no longer binds by email:
-- the pending session carries the IdP identity, and it is bound only after
-- that administrator proves their console second factor. Nullable columns on
-- short-lived rows: no backfill, no rewrite.
ALTER TABLE admin_sessions
    ADD COLUMN IF NOT EXISTS pending_idp_issuer  TEXT,
    ADD COLUMN IF NOT EXISTS pending_idp_subject TEXT;

ALTER TABLE admin_sessions DROP CONSTRAINT IF EXISTS chk_admin_sessions_pending_idp;
ALTER TABLE admin_sessions ADD CONSTRAINT chk_admin_sessions_pending_idp CHECK (
    (pending_idp_issuer IS NULL) = (pending_idp_subject IS NULL)
    AND (pending_idp_issuer IS NULL OR NOT mfa_verified)
);

COMMENT ON COLUMN admin_sessions.pending_idp_issuer IS
    'Pending (not yet MFA-verified) session only: IdP issuer to bind after the console second factor.';
COMMENT ON COLUMN admin_sessions.pending_idp_subject IS
    'Pending (not yet MFA-verified) session only: IdP subject to bind after the console second factor.';
