-- Retire the assets.* sub-modules (assets.domains, assets.ips, ...).
--
-- They existed to gate the per-type asset pages (/assets/domains,
-- /assets/ip-addresses, ...). Those pages are gone: every type is a view of
-- the one inventory at /assets?types=<type>, driven by the asset type
-- registry (api/configs/asset-types.yaml). Nothing reads the rows any more,
-- but they still showed up as toggles in the tenant module settings, where
-- switching one off did nothing.
--
-- The whole inventory stays gated by the top-level `assets` module.
-- Idempotent: a second run finds no assets.* row left.

-- asset_types.module_id is informational (nothing gates on it); point the
-- types at the parent module instead of losing the link.
UPDATE asset_types SET module_id = 'assets' WHERE module_id LIKE 'assets.%';

-- Same for any permission or event type filed under a sub-module.
UPDATE permissions SET module_id = 'assets' WHERE module_id LIKE 'assets.%';
UPDATE event_types SET module_id = 'assets' WHERE module_id LIKE 'assets.%';

-- Tenant overrides of a sub-module toggle (tenant_modules has no ON DELETE).
DELETE FROM tenant_modules WHERE module_id LIKE 'assets.%';

DELETE FROM modules WHERE parent_module_id = 'assets' OR id LIKE 'assets.%';

COMMENT ON COLUMN modules.parent_module_id IS 'Parent module for sub-modules (e.g., integrations.scm)';
