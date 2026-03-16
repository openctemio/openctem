-- Finding Group Assignments: tracks which findings are assigned to which groups via assignment rules.
CREATE TABLE IF NOT EXISTS finding_group_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES assignment_rules(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(finding_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_fga_tenant_finding ON finding_group_assignments(tenant_id, finding_id);
CREATE INDEX IF NOT EXISTS idx_fga_tenant_group ON finding_group_assignments(tenant_id, group_id);
CREATE INDEX IF NOT EXISTS idx_fga_rule ON finding_group_assignments(rule_id);
CREATE INDEX IF NOT EXISTS idx_fga_tenant_rule ON finding_group_assignments(tenant_id, rule_id) WHERE rule_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fga_finding ON finding_group_assignments(finding_id);
