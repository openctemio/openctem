-- =============================================================================
-- Migration 000056: Drop Redundant Indexes
-- OpenCTEM OSS Edition
-- =============================================================================
-- Removes single-column indexes that are left-prefixes of tenant-scoped
-- composite indexes.  In a multi-tenant app every query includes tenant_id,
-- so the composite index fully covers the single-column one.
--
-- Findings: 12 indexes removed (70 → 58)
-- Assets:    6 indexes removed (47 → 41)
-- =============================================================================

-- =============================================================================
-- 1. Findings – High Confidence (single-col subsumed by tenant composite)
-- =============================================================================

-- idx_findings_tenant_id ← idx_findings_tenant_id_pk (tenant_id, id)
DROP INDEX IF EXISTS idx_findings_tenant_id;

-- idx_findings_asset_id ← idx_findings_tenant_asset (tenant_id, asset_id)
DROP INDEX IF EXISTS idx_findings_asset_id;

-- idx_findings_severity ← idx_findings_tenant_severity (tenant_id, severity)
DROP INDEX IF EXISTS idx_findings_severity;

-- idx_findings_status ← idx_findings_tenant_status (tenant_id, status)
DROP INDEX IF EXISTS idx_findings_status;

-- idx_findings_tool_name ← idx_findings_tenant_tool_name (tenant_id, tool_name)
DROP INDEX IF EXISTS idx_findings_tool_name;

-- idx_findings_finding_type ← idx_findings_tenant_type (tenant_id, finding_type)
DROP INDEX IF EXISTS idx_findings_finding_type;

-- idx_findings_scan_id ← idx_findings_tenant_scan_id (tenant_id, scan_id)
DROP INDEX IF EXISTS idx_findings_scan_id;

-- idx_findings_created_at ← idx_findings_tenant_created_at (tenant_id, created_at DESC)
DROP INDEX IF EXISTS idx_findings_created_at;

-- =============================================================================
-- 2. Findings – Lower Confidence (composite left-prefix overlaps)
-- =============================================================================

-- idx_findings_asset_status (asset_id, status) ← idx_findings_tenant_asset_status (tenant_id, asset_id, status)
DROP INDEX IF EXISTS idx_findings_asset_status;

-- idx_findings_secret_service (secret_service) ← idx_findings_secret_service_valid (secret_service, secret_valid)
DROP INDEX IF EXISTS idx_findings_secret_service;

-- idx_findings_web3_chain (web3_chain) ← idx_findings_web3_chain_contract (web3_chain, web3_contract_address)
DROP INDEX IF EXISTS idx_findings_web3_chain;

-- idx_findings_compliance_framework ← idx_findings_compliance_framework_result
DROP INDEX IF EXISTS idx_findings_compliance_framework;

-- =============================================================================
-- 3. Assets – High Confidence
-- =============================================================================

-- idx_assets_tenant_id ← idx_assets_tenant_id_pk (tenant_id, id)
DROP INDEX IF EXISTS idx_assets_tenant_id;

-- idx_assets_asset_type ← idx_assets_tenant_type (tenant_id, asset_type)
DROP INDEX IF EXISTS idx_assets_asset_type;

-- idx_assets_status ← idx_assets_tenant_status (tenant_id, status)
DROP INDEX IF EXISTS idx_assets_status;

-- idx_assets_name ← idx_assets_tenant_name (tenant_id, name)
DROP INDEX IF EXISTS idx_assets_name;

-- idx_assets_risk_score ← idx_assets_tenant_risk (tenant_id, risk_score DESC)
DROP INDEX IF EXISTS idx_assets_risk_score;

-- idx_assets_data_classification ← idx_assets_tenant_compliance (tenant_id, data_classification)
DROP INDEX IF EXISTS idx_assets_data_classification;
