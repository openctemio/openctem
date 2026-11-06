-- Read-only grace for the named features below module level (sso.enforcement,
-- scim, ...): tenant_module_grace held module ids only (foreign key to
-- modules), so a denied named feature never got its grace and SSO enforcement
-- or SCIM stopped at once. The key is now a module id or a named feature;
-- StartGrace admits only those two kinds.

ALTER TABLE tenant_module_grace DROP CONSTRAINT IF EXISTS tenant_module_grace_module_id_fkey;

COMMENT ON COLUMN tenant_module_grace.module_id IS
    'A module id or a named feature (pkg/domain/limits NamedFeatures)';
