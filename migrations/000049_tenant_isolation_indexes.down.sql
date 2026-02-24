-- =============================================================================
-- Migration 000049 DOWN: Drop Tenant Isolation Composite Indexes
-- =============================================================================

-- Exposure Events
DROP INDEX IF EXISTS idx_exposure_events_tenant_id_pk;

-- Suppression Rules
DROP INDEX IF EXISTS idx_suppression_rules_tenant_id_pk;

-- Integrations
DROP INDEX IF EXISTS idx_integrations_tenant_id_pk;

-- Agents
DROP INDEX IF EXISTS idx_agents_tenant_status;
DROP INDEX IF EXISTS idx_agents_tenant_id_pk;

-- Scans
DROP INDEX IF EXISTS idx_scans_tenant_id_pk;

-- Assets
DROP INDEX IF EXISTS idx_assets_tenant_name;
DROP INDEX IF EXISTS idx_assets_tenant_id_pk;

-- Findings
DROP INDEX IF EXISTS idx_findings_tenant_tool_name;
DROP INDEX IF EXISTS idx_findings_tenant_created_at;
DROP INDEX IF EXISTS idx_findings_tenant_id_pk;
DROP INDEX IF EXISTS idx_findings_tenant_scan_id;
