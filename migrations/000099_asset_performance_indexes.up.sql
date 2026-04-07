-- Performance indexes for asset queries
-- Compound index for common filtered list queries (tenant + type + criticality + status)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_type_crit_status
    ON assets(tenant_id, asset_type, criticality, status);

-- Compound index for discovery source queries per tenant
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_discovery_source
    ON assets(tenant_id, discovery_source)
    WHERE discovery_source IS NOT NULL;

-- Partial index for critical assets with PII data (CTEM analytics)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_critical_pii
    ON assets(tenant_id, criticality)
    WHERE pii_data_exposed = true;

-- Index on findings.asset_id for faster EXISTS subquery and JOIN
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_asset_id_status
    ON findings(asset_id, status);
