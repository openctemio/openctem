ALTER TABLE sessions DROP CONSTRAINT IF EXISTS chk_sessions_auth_method;
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_method;
