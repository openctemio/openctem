-- Composite indexes for scope rule queries
-- These support the real-time hooks and background reconciliation controller.

-- Scope rules: list active rules per tenant (used by EvaluateAsset, background controller)
CREATE INDEX IF NOT EXISTS idx_scope_rules_tenant_active
    ON group_asset_scope_rules (tenant_id, is_active)
    WHERE is_active = true;

-- Scope rules: list active rules per group (used by ReconcileGroup)
CREATE INDEX IF NOT EXISTS idx_scope_rules_group_tenant_active
    ON group_asset_scope_rules (group_id, tenant_id, is_active)
    WHERE is_active = true;

-- Asset owners: lookup by assignment source (used by stale cleanup in EvaluateAsset)
CREATE INDEX IF NOT EXISTS idx_asset_owners_source
    ON asset_owners (asset_id, assignment_source)
    WHERE assignment_source = 'scope_rule';
