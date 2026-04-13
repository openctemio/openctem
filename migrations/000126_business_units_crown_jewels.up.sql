-- Business units: organizational grouping for risk aggregation.
CREATE TABLE IF NOT EXISTS business_units (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    owner_name VARCHAR(255),
    owner_email VARCHAR(255),
    -- Risk aggregation (cached from linked assets)
    asset_count INT DEFAULT 0,
    finding_count INT DEFAULT 0,
    avg_risk_score NUMERIC(5,2) DEFAULT 0,
    critical_finding_count INT DEFAULT 0,
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_business_units_tenant ON business_units(tenant_id);

-- Link assets to business units (many-to-many)
CREATE TABLE IF NOT EXISTS business_unit_assets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    business_unit_id UUID NOT NULL REFERENCES business_units(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, business_unit_id, asset_id)
);

CREATE INDEX idx_bu_assets_bu ON business_unit_assets(business_unit_id);
CREATE INDEX idx_bu_assets_asset ON business_unit_assets(asset_id);

-- Crown jewels: mark critical assets with business impact scoring.
-- This is an attribute on existing assets, not a separate entity.
-- Add columns to assets table.
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS is_crown_jewel BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS business_impact_score NUMERIC(5,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS business_impact_notes TEXT DEFAULT '';

CREATE INDEX idx_assets_crown_jewel ON assets(tenant_id, is_crown_jewel) WHERE is_crown_jewel = TRUE;
