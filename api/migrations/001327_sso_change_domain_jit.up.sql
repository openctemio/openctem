-- A platform administrator's change that raises a domain's just-in-time
-- provisioning (admits newcomers, or gives them a higher role) waits for an
-- owner of the organization like any SSO change (RFC-058).
ALTER TABLE sso_pending_changes DROP CONSTRAINT IF EXISTS chk_sso_pending_changes_kind;
ALTER TABLE sso_pending_changes ADD CONSTRAINT chk_sso_pending_changes_kind
    CHECK (kind IN ('saml_config', 'idp_create', 'idp_update', 'domain_jit'));
