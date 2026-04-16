-- Migration 000152: Business Services + Regression Tracking (Phase 3 — 100% completion)
--
-- Business Services: distinct from Business Units. A service represents a
-- specific business capability (Payment Processing, Customer Login) that
-- spans multiple assets and often multiple business units.
--
-- Regression Tracking: mark findings that were resolved and later reopened.

-- ============================================================
-- Business Services
-- ============================================================
CREATE TABLE IF NOT EXISTS business_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    criticality VARCHAR(20) DEFAULT 'medium'
      CHECK (criticality IN ('critical','high','medium','low')),

    -- Compliance scope: which frameworks this service falls under
    compliance_scope TEXT[],  -- ["PCI-DSS", "HIPAA"]

    -- Data handling
    handles_pii BOOLEAN DEFAULT false,
    handles_phi BOOLEAN DEFAULT false,
    handles_financial BOOLEAN DEFAULT false,

    -- SLA targets for this service
    availability_target DECIMAL(5,2),  -- e.g., 99.99
    rpo_minutes INT,  -- recovery point objective
    rto_minutes INT,  -- recovery time objective

    owner_name VARCHAR(200),
    owner_email VARCHAR(200),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_business_services_tenant
  ON business_services(tenant_id);
CREATE INDEX IF NOT EXISTS idx_business_services_criticality
  ON business_services(tenant_id, criticality);

-- Link services to assets (many-to-many)
CREATE TABLE IF NOT EXISTS business_service_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    service_id UUID NOT NULL REFERENCES business_services(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    dependency_type VARCHAR(30) DEFAULT 'runs_on'
      CHECK (dependency_type IN ('runs_on','depends_on','stores_data_in','authenticates_via','monitors')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (service_id, asset_id, dependency_type)
);

CREATE INDEX IF NOT EXISTS idx_business_service_assets_service
  ON business_service_assets(service_id);
CREATE INDEX IF NOT EXISTS idx_business_service_assets_asset
  ON business_service_assets(asset_id);

-- ============================================================
-- Regression Tracking
-- ============================================================
-- Add regression flag to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_regression BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reopen_count INT DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_reopened_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_findings_regression
  ON findings(tenant_id) WHERE is_regression = true;

-- Regression events log
CREATE TABLE IF NOT EXISTS finding_regression_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    previous_resolution VARCHAR(50),
    reopened_by UUID,
    reason TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_regression_events_tenant
  ON finding_regression_events(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_regression_events_finding
  ON finding_regression_events(finding_id);
