-- Migration 000142: Priority Classes P0-P3 + EPSS/KEV Enrichment (RFC-004)
--
-- Adds threat intel enrichment fields and priority classification to findings.
-- Enables CTEM-aligned prioritization: business context + exploit evidence + reachability.

-- ============================================================
-- Step 1: Threat Intel Enrichment on Findings
-- ============================================================
ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss_score DECIMAL(6,5);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_in_kev BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS kev_due_date DATE;

-- ============================================================
-- Step 2: Priority Classification on Findings
-- ============================================================
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_class VARCHAR(2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_class_reason TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_class_override BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_class_overridden_by UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_class_overridden_at TIMESTAMPTZ;

-- ============================================================
-- Step 3: Reachability Context (from attack path scoring)
-- ============================================================
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_reachable BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reachable_from_count INT DEFAULT 0;

-- ============================================================
-- Step 4: Constraints
-- ============================================================
ALTER TABLE findings ADD CONSTRAINT chk_priority_class
  CHECK (priority_class IS NULL OR priority_class IN ('P0','P1','P2','P3'));

-- ============================================================
-- Step 5: Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_findings_priority_class
  ON findings(tenant_id, priority_class)
  WHERE priority_class IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_findings_kev
  ON findings(tenant_id)
  WHERE is_in_kev = true;

CREATE INDEX IF NOT EXISTS idx_findings_reachable
  ON findings(tenant_id)
  WHERE is_reachable = true;

-- ============================================================
-- Step 6: Priority Override Rules (per-tenant configurable)
-- ============================================================
CREATE TABLE IF NOT EXISTS priority_override_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    priority_class VARCHAR(2) NOT NULL
      CHECK (priority_class IN ('P0','P1','P2','P3')),
    conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active BOOLEAN DEFAULT true,
    evaluation_order INT DEFAULT 0,
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_priority_rules_tenant_active
  ON priority_override_rules(tenant_id, evaluation_order DESC)
  WHERE is_active = true;

-- ============================================================
-- Step 7: Priority Class Audit Log
-- ============================================================
CREATE TABLE IF NOT EXISTS priority_class_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    previous_class VARCHAR(2),
    new_class VARCHAR(2) NOT NULL,
    reason TEXT NOT NULL,
    source VARCHAR(20) NOT NULL,
    rule_id UUID,
    actor_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_priority_audit_finding
  ON priority_class_audit_log(finding_id, created_at DESC);

-- ============================================================
-- Step 8: SLA Policy Priority Class Days
-- ============================================================
ALTER TABLE sla_policies ADD COLUMN IF NOT EXISTS p0_days INT DEFAULT 7;
ALTER TABLE sla_policies ADD COLUMN IF NOT EXISTS p1_days INT DEFAULT 30;
ALTER TABLE sla_policies ADD COLUMN IF NOT EXISTS p2_days INT DEFAULT 60;
ALTER TABLE sla_policies ADD COLUMN IF NOT EXISTS p3_days INT DEFAULT 180;

-- ============================================================
-- Step 9: Seed default override rules for ORG tenant
-- ============================================================
INSERT INTO priority_override_rules (tenant_id, name, description, priority_class, conditions, evaluation_order, created_at, updated_at)
SELECT t.id,
       'KEV + Reachable = P0',
       'Known exploited vulnerability that is reachable from attacker perspective',
       'P0',
       '[{"field":"is_in_kev","operator":"eq","value":true},{"field":"is_reachable","operator":"eq","value":true}]'::jsonb,
       100,
       NOW(), NOW()
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM priority_override_rules WHERE tenant_id = t.id)
UNION ALL
SELECT t.id,
       'KEV + Crown Jewel = P0',
       'Known exploited vulnerability on crown jewel asset',
       'P0',
       '[{"field":"is_in_kev","operator":"eq","value":true},{"field":"asset_is_crown_jewel","operator":"eq","value":true}]'::jsonb,
       99,
       NOW(), NOW()
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM priority_override_rules WHERE tenant_id = t.id)
UNION ALL
SELECT t.id,
       'High EPSS + Reachable + Critical Asset = P1',
       'High exploitation probability on reachable critical asset',
       'P1',
       '[{"field":"epss_score","operator":"gte","value":0.3},{"field":"is_reachable","operator":"eq","value":true},{"field":"asset_criticality","operator":"in","value":["critical","high"]}]'::jsonb,
       90,
       NOW(), NOW()
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM priority_override_rules WHERE tenant_id = t.id)
UNION ALL
SELECT t.id,
       'EPSS >= 0.1 + Reachable + High Asset = P1',
       'Moderate-high exploitation probability on reachable high-impact asset',
       'P1',
       '[{"field":"epss_score","operator":"gte","value":0.1},{"field":"is_reachable","operator":"eq","value":true},{"field":"asset_criticality","operator":"in","value":["critical","high"]}]'::jsonb,
       89,
       NOW(), NOW()
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM priority_override_rules WHERE tenant_id = t.id);
