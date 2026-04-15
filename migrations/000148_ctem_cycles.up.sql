-- Migration 000148: CTEM Cycles (RFC-005 Gap 3)
--
-- A CTEM cycle is a time-boxed assessment period (typically quarterly).
-- Each cycle records: scope, threat model, what was found, what was fixed.

CREATE TABLE IF NOT EXISTS ctem_cycles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'planning'
      CHECK (status IN ('planning','active','review','closed')),
    start_date DATE,
    end_date DATE,
    charter JSONB DEFAULT '{}'::jsonb,
    -- charter: {business_priorities[], risk_appetite, in_scope_services[], objectives[]}
    closed_by UUID,
    closed_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ctem_cycles_tenant
  ON ctem_cycles(tenant_id, status);

-- Scope snapshot: frozen set of assets at cycle activation
CREATE TABLE IF NOT EXISTS ctem_cycle_scope_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_id UUID NOT NULL REFERENCES ctem_cycles(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL,
    scope_target_id UUID,
    included_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cycle_snapshots_cycle
  ON ctem_cycle_scope_snapshots(cycle_id);

-- Metrics computed at cycle close (and intermediate checkpoints)
CREATE TABLE IF NOT EXISTS ctem_cycle_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_id UUID NOT NULL REFERENCES ctem_cycles(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    -- Types: risk_before, risk_after, findings_discovered, findings_resolved,
    --        mttr_hours, sla_compliance_pct, p0_resolved, p1_resolved
    value DECIMAL(12,2) NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cycle_metrics
  ON ctem_cycle_metrics(cycle_id, metric_type);

-- Link attacker profiles to cycles
CREATE TABLE IF NOT EXISTS ctem_cycle_attacker_profiles (
    cycle_id UUID NOT NULL REFERENCES ctem_cycles(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES attacker_profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (cycle_id, profile_id)
);
