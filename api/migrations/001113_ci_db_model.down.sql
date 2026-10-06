-- The creator's email is not restored (it was dropped); the column comes back
-- empty.
ALTER TABLE ci_gate_overrides ADD COLUMN IF NOT EXISTS created_by_email VARCHAR(320) NOT NULL DEFAULT '';

ALTER TABLE ci_gate_policies ADD COLUMN IF NOT EXISTS scope_id UUID;
UPDATE ci_gate_policies SET scope_id = COALESCE(repository_asset_id, business_unit_id);
DROP INDEX IF EXISTS uq_ci_gate_policies_scope;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS fk_ci_gate_policies_repository;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS fk_ci_gate_policies_business_unit;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_scope;
ALTER TABLE ci_gate_policies DROP COLUMN IF EXISTS repository_asset_id;
ALTER TABLE ci_gate_policies DROP COLUMN IF EXISTS business_unit_id;
ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_scope CHECK (
    scope_type IN ('tenant', 'business_unit', 'repository')
    AND ((scope_type = 'tenant') = (scope_id IS NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS uq_ci_gate_policies_scope
    ON ci_gate_policies (tenant_id, scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid));
ALTER TABLE business_units DROP CONSTRAINT IF EXISTS uq_business_units_tenant_id;

ALTER TABLE ci_pipelines DROP CONSTRAINT IF EXISTS fk_ci_pipelines_trust_config;
ALTER TABLE ci_pipelines ADD CONSTRAINT ci_pipelines_trust_config_id_fkey
    FOREIGN KEY (trust_config_id) REFERENCES ci_trust_configs (id) ON DELETE SET NULL;
ALTER TABLE ci_runs DROP CONSTRAINT IF EXISTS fk_ci_runs_trust_config;
ALTER TABLE ci_runs ADD CONSTRAINT ci_runs_trust_config_id_fkey
    FOREIGN KEY (trust_config_id) REFERENCES ci_trust_configs (id) ON DELETE SET NULL;
