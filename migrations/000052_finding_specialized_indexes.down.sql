-- =============================================================================
-- Migration 000052 DOWN: Drop Finding Specialized Indexes
-- =============================================================================

-- Security-critical composite
DROP INDEX IF EXISTS idx_findings_high_risk_exposure;
DROP INDEX IF EXISTS idx_assets_sensitive_data;

-- Resolution & component tracking
DROP INDEX IF EXISTS idx_findings_component_tenant;
DROP INDEX IF EXISTS idx_findings_resolved_by;

-- Remediation
DROP INDEX IF EXISTS idx_findings_fix_available;
DROP INDEX IF EXISTS idx_findings_has_remediation;

-- ASVS
DROP INDEX IF EXISTS idx_findings_asvs_control;
DROP INDEX IF EXISTS idx_findings_asvs_section;

-- Misconfiguration
DROP INDEX IF EXISTS idx_findings_misconfig_type_policy;
DROP INDEX IF EXISTS idx_findings_misconfig_resource_type;

-- Web3
DROP INDEX IF EXISTS idx_findings_web3_chain_contract;
DROP INDEX IF EXISTS idx_findings_web3_swc;

-- Compliance
DROP INDEX IF EXISTS idx_findings_compliance_result;
DROP INDEX IF EXISTS idx_findings_compliance_control;

-- Secrets
DROP INDEX IF EXISTS idx_findings_secret_service_valid;
DROP INDEX IF EXISTS idx_findings_secret_valid;
