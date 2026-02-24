-- =============================================================================
-- Migration 000049: Tenant Isolation Composite Indexes
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds composite (tenant_id, ...) indexes that dramatically speed up
-- tenant-scoped queries.  Every repository method that filters by tenant_id
-- benefits from having the tenant column as the leading key.
--
-- Indexes that already exist in earlier migrations are skipped here.
-- All CREATE INDEX statements use IF NOT EXISTS for idempotency.
-- =============================================================================

-- =============================================================================
-- Findings
-- =============================================================================
-- Existing: idx_findings_tenant_id, idx_findings_tenant_fingerprint (UNIQUE),
--           idx_findings_tenant_asset, idx_findings_tenant_status,
--           idx_findings_tenant_severity, idx_findings_tenant_type,
--           idx_findings_tenant_asset_status

-- (tenant_id, scan_id) — DeleteByScanID, CountBySeverityForScan
CREATE INDEX IF NOT EXISTS idx_findings_tenant_scan_id
    ON findings(tenant_id, scan_id);

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_findings_tenant_id_pk
    ON findings(tenant_id, id);

-- (tenant_id, created_at DESC) — List with default sort order
CREATE INDEX IF NOT EXISTS idx_findings_tenant_created_at
    ON findings(tenant_id, created_at DESC);

-- (tenant_id, tool_name) — AutoResolveStale queries
CREATE INDEX IF NOT EXISTS idx_findings_tenant_tool_name
    ON findings(tenant_id, tool_name);

-- =============================================================================
-- Assets
-- =============================================================================
-- Existing: idx_assets_tenant_id, idx_assets_tenant_type,
--           idx_assets_tenant_status, idx_assets_tenant_risk,
--           idx_assets_tenant_compliance

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_assets_tenant_id_pk
    ON assets(tenant_id, id);

-- (tenant_id, name) — search by name within tenant
CREATE INDEX IF NOT EXISTS idx_assets_tenant_name
    ON assets(tenant_id, name);

-- =============================================================================
-- Scans
-- =============================================================================
-- Existing: idx_scans_tenant, idx_scans_tenant_status

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_scans_tenant_id_pk
    ON scans(tenant_id, id);

-- =============================================================================
-- Agents
-- =============================================================================
-- Existing: idx_agents_tenant_id

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_agents_tenant_id_pk
    ON agents(tenant_id, id);

-- (tenant_id, status) — filtering active agents
CREATE INDEX IF NOT EXISTS idx_agents_tenant_status
    ON agents(tenant_id, status);

-- =============================================================================
-- Integrations
-- =============================================================================
-- Existing: idx_integrations_tenant_id, idx_integrations_tenant_category,
--           idx_integrations_tenant_provider

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_integrations_tenant_id_pk
    ON integrations(tenant_id, id);

-- =============================================================================
-- Suppression Rules
-- =============================================================================
-- Existing: idx_suppression_rules_tenant

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_suppression_rules_tenant_id_pk
    ON suppression_rules(tenant_id, id);

-- =============================================================================
-- Exposure Events
-- =============================================================================
-- Existing: idx_exposure_events_tenant, idx_exposure_events_tenant_state,
--           idx_exposure_events_tenant_severity, idx_exposure_events_tenant_type

-- (tenant_id, id) — GetByID with tenant isolation
CREATE INDEX IF NOT EXISTS idx_exposure_events_tenant_id_pk
    ON exposure_events(tenant_id, id);
