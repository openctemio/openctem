-- =============================================================================
-- Migration 000060 DOWN: Revert Schema Fixes
-- =============================================================================

-- 9. Remove workflow_node_runs UNIQUE index
DROP INDEX IF EXISTS idx_uq_workflow_node_run;

-- 8. Remove workflow_edges constraints
ALTER TABLE workflow_edges DROP CONSTRAINT IF EXISTS chk_workflow_edge_no_self_loop;
DROP INDEX IF EXISTS idx_uq_workflow_edge;

-- 7. Restore original asset_components UNIQUE constraint
DROP INDEX IF EXISTS idx_uq_asset_component;
ALTER TABLE asset_components
    ADD CONSTRAINT unique_component UNIQUE (tenant_id, asset_id, name, version, branch_id);

-- 6. Revert target_asset_type_mappings fixes
UPDATE target_asset_type_mappings
SET asset_type = 'ip_address', updated_at = NOW()
WHERE asset_type = 'ip'
  AND target_type IN ('ip', 'host');

UPDATE target_asset_type_mappings
SET asset_type = 'serverless', updated_at = NOW()
WHERE asset_type = 'serverless_function'
  AND target_type = 'cloud';

-- 5. Remove added asset types and recon category
DELETE FROM asset_types WHERE code IN (
    'unclassified', 'discovered_url', 'http_service', 'open_port',
    'server', 'vpc', 'subnet', 'firewall', 'load_balancer', 'compute',
    'container', 'container_registry', 'storage', 's3_bucket', 'certificate'
);
DELETE FROM asset_type_categories WHERE code = 'recon';

-- 4. Remove asset_owners CHECK constraint
ALTER TABLE asset_owners DROP CONSTRAINT IF EXISTS chk_asset_owners_has_owner;

-- 3. Remove asset_owners unique partial indexes
DROP INDEX IF EXISTS idx_uq_asset_owners_asset_user;
DROP INDEX IF EXISTS idx_uq_asset_owners_asset_group;

-- 1 & 2. Revert fingerprint columns
ALTER TABLE findings ALTER COLUMN fingerprint TYPE VARCHAR(64);
ALTER TABLE exposure_events ALTER COLUMN fingerprint TYPE VARCHAR(64);
