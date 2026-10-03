-- Records WHICH organization's identity provider issued a federated session.
--
-- Users and sessions are global: one sign-in can be exchanged for an access
-- token in every organization the account belongs to. A sign-in through org B's
-- SAML/OIDC provider (or through social OAuth) therefore must not satisfy org
-- A's "SSO enforced" or "2FA required" policy. The exemption from those two
-- policies now applies only when the session is used for the organization whose
-- IdP issued it (idp_tenant_id = the token's tenant).
--
-- NULL means "no issuing organization": password sessions, social OAuth
-- (GitHub/Google/personal Microsoft) and every session created before this
-- migration. Such sessions are never exempt (fail closed); members of an
-- SSO-enforced organization holding a pre-migration SSO session sign in again
-- through their organization's IdP.
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS idp_tenant_id UUID NULL REFERENCES tenants(id) ON DELETE SET NULL;

COMMENT ON COLUMN sessions.idp_tenant_id IS 'Organization whose SAML/OIDC identity provider issued this federated session. Only that organization treats the session as an SSO sign-in (SSO enforcement, 2FA requirement). NULL for password, social OAuth and pre-000269 sessions.';
