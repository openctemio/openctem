ALTER TABLE admin_sessions DROP CONSTRAINT IF EXISTS chk_admin_sessions_pending_idp;
ALTER TABLE admin_sessions
    DROP COLUMN IF EXISTS pending_idp_subject,
    DROP COLUMN IF EXISTS pending_idp_issuer;
