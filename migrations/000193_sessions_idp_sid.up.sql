-- OIDC Back-Channel Logout 1.0 support: bind a federated session to the IdP
-- session it came from so an IdP-initiated logout_token can revoke exactly the
-- right sessions.
--
--   idp_issuer — the verified id_token `iss` (the provider that owns the session).
--                Scopes revocation per-provider: a logout_token from provider X
--                can only revoke sessions whose idp_issuer == X's issuer.
--   idp_sid    — the id_token `sid` (IdP session id). Revoke a specific session.
--   idp_sub    — the id_token `sub` (IdP subject). Revoke all of a user's
--                sessions for the issuer when the logout_token carries only `sub`.
--
-- All nullable: only OIDC/OAuth sessions that carried these claims are populated;
-- local password and SAML sessions leave them NULL and are never matched.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS idp_issuer TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS idp_sid TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS idp_sub TEXT;

-- Lookups are always issuer-scoped (never match a sid/sub across providers).
CREATE INDEX IF NOT EXISTS idx_sessions_idp_issuer_sid
    ON sessions (idp_issuer, idp_sid)
    WHERE idp_sid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_idp_issuer_sub
    ON sessions (idp_issuer, idp_sub)
    WHERE idp_sub IS NOT NULL;

COMMENT ON COLUMN sessions.idp_issuer IS 'Verified OIDC id_token iss for federated sessions; scopes back-channel logout per-provider. NULL for local/SAML sessions.';
COMMENT ON COLUMN sessions.idp_sid IS 'OIDC id_token sid (IdP session id) for OIDC Back-Channel Logout 1.0. NULL when absent.';
COMMENT ON COLUMN sessions.idp_sub IS 'OIDC id_token sub (IdP subject) for sub-only back-channel logout. NULL when absent.';
