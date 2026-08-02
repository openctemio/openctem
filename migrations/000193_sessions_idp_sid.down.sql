DROP INDEX IF EXISTS idx_sessions_idp_issuer_sub;
DROP INDEX IF EXISTS idx_sessions_idp_issuer_sid;
ALTER TABLE sessions DROP COLUMN IF EXISTS idp_sub;
ALTER TABLE sessions DROP COLUMN IF EXISTS idp_sid;
ALTER TABLE sessions DROP COLUMN IF EXISTS idp_issuer;
