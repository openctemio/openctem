-- Composite indexes for access control query optimization.

-- Scope rules: optimize ListActiveScopeRulesByGroup (group_id + tenant_id + is_active + priority)
CREATE INDEX IF NOT EXISTS idx_scope_rules_group_tenant_active_priority
    ON group_asset_scope_rules(group_id, tenant_id, is_active, priority DESC)
    WHERE is_active = TRUE;

-- Scope rules: optimize CountScopeRules and ListScopeRules (group_id + tenant_id)
CREATE INDEX IF NOT EXISTS idx_scope_rules_group_tenant
    ON group_asset_scope_rules(group_id, tenant_id);

-- Assignment rules: optimize ListActiveRulesByPriority (tenant_id + is_active + priority)
CREATE INDEX IF NOT EXISTS idx_assignment_rules_tenant_active_priority
    ON assignment_rules(tenant_id, is_active, priority DESC)
    WHERE is_active = TRUE;
