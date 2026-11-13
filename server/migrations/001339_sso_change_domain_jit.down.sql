DELETE FROM sso_pending_changes WHERE kind = 'domain_jit';
ALTER TABLE sso_pending_changes DROP CONSTRAINT IF EXISTS chk_sso_pending_changes_kind;
ALTER TABLE sso_pending_changes ADD CONSTRAINT chk_sso_pending_changes_kind
    CHECK (kind IN ('saml_config', 'idp_create', 'idp_update'));
