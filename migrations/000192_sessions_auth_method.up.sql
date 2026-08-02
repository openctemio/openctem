-- Records HOW a session was authenticated so the per-tenant SSO-enforcement gate
-- can tell a local password login apart from a federated (SSO/OAuth/SAML) login.
-- An SSO-enforced tenant refuses password sessions but always admits federated
-- ones; the tenant OWNER is the break-glass exception (can always password-login,
-- so enabling SSO can never lock every administrator out).
--
-- Existing rows default to 'password' — fail-safe: an unmarked (pre-migration)
-- session must not silently pass enforcement.
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS auth_method VARCHAR(20) NOT NULL DEFAULT 'password';

ALTER TABLE sessions
    DROP CONSTRAINT IF EXISTS chk_sessions_auth_method;
ALTER TABLE sessions
    ADD CONSTRAINT chk_sessions_auth_method CHECK (auth_method IN ('password', 'sso', 'saml'));

COMMENT ON COLUMN sessions.auth_method IS 'How the session was authenticated: password (local login), sso (federated OIDC/OAuth), or saml. Used by per-tenant SSO enforcement.';
