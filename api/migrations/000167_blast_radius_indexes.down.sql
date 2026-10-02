-- Drop blast-radius indexes added in 000167.

DROP INDEX IF EXISTS idx_findings_tenant_vulnerability;
DROP INDEX IF EXISTS idx_asset_components_tenant_component;
