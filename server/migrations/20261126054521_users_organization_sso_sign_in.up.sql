-- Which organization's single sign-on manages an account (research 539).
--
-- sso_signed_in_at: the first time an organization's SSO (OIDC or SAML)
--   signed the account in. Set on every organization sign-on path, whether or
--   not the IdP sent a stable identifier. A password-less account with it set
--   gets no password by forgot-password or a set-password link.
-- sso_tenant_id: the organization whose SSO signed it in first. Only an
--   active owner of this organization keeps forgot-password (break-glass);
--   owning any other organization does not count. Never overwritten.
ALTER TABLE users
    ADD COLUMN sso_signed_in_at timestamptz NULL,
    ADD COLUMN sso_tenant_id uuid NULL REFERENCES tenants(id) ON DELETE SET NULL;

COMMENT ON COLUMN users.sso_signed_in_at IS
    'First sign-in through an organization''s single sign-on. A password-less account with it set gets no self-service password.';
COMMENT ON COLUMN users.sso_tenant_id IS
    'Organization whose single sign-on signed the account in first; its active owners keep forgot-password.';

-- Accounts an organization's SSO already signed in, known by their identity
-- rows. A SAML identity names its organization; an OIDC identity does not,
-- so sso_tenant_id is filled at that account's next SSO sign-in.
UPDATE users u
SET sso_signed_in_at = s.first_at,
    sso_tenant_id = s.tenant_id
FROM (
    SELECT ui.user_id,
           min(COALESCE(ui.last_used_at, ui.created_at)) AS first_at,
           (array_agg(ui.scope_tenant_id ORDER BY ui.created_at)
               FILTER (WHERE ui.scope_tenant_id IS NOT NULL))[1] AS tenant_id
    FROM user_identities ui
    WHERE ui.source = 'sso'
    GROUP BY ui.user_id
) s
WHERE u.id = s.user_id
  AND u.sso_signed_in_at IS NULL;
