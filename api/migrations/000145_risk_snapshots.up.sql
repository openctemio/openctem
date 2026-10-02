-- Migration 000145: Risk Snapshots for trend analysis (RFC-005 Gap 4)
--
-- Daily snapshots per tenant: risk score, finding counts, SLA compliance,
-- MTTR by severity, priority class distribution.

CREATE TABLE IF NOT EXISTS risk_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL,

    -- Risk metrics
    risk_score_avg DECIMAL(5,2) DEFAULT 0,
    risk_score_max DECIMAL(5,2) DEFAULT 0,

    -- Finding counts
    findings_open INT DEFAULT 0,
    findings_closed_today INT DEFAULT 0,

    -- Exposure
    exposures_active INT DEFAULT 0,

    -- SLA
    sla_compliance_pct DECIMAL(5,2) DEFAULT 0,

    -- MTTR by severity (hours)
    mttr_critical_hours DECIMAL(8,2),
    mttr_high_hours DECIMAL(8,2),
    mttr_medium_hours DECIMAL(8,2),
    mttr_low_hours DECIMAL(8,2),

    -- Priority class distribution
    p0_open INT DEFAULT 0,
    p1_open INT DEFAULT 0,
    p2_open INT DEFAULT 0,
    p3_open INT DEFAULT 0,

    -- Data quality (inline for simplicity)
    asset_ownership_pct DECIMAL(5,2) DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_risk_snapshots_range
  ON risk_snapshots(tenant_id, snapshot_date DESC);
