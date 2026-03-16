-- =============================================================================
-- Migration 000052: Finding Specialized Indexes
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds partial and composite indexes for specialized finding queries:
-- secrets, compliance, web3, misconfiguration, ASVS, remediation, and
-- component lookups.  All use IF NOT EXISTS for idempotency.
-- =============================================================================

-- =============================================================================
-- 1. Secret Finding Indexes
-- =============================================================================

-- Valid secrets that need attention
CREATE INDEX IF NOT EXISTS idx_findings_secret_valid
    ON findings(tenant_id, secret_valid)
    WHERE finding_type = 'secret' AND secret_valid IS NOT NULL;

-- Secret service + validity composite for dashboard queries
CREATE INDEX IF NOT EXISTS idx_findings_secret_service_valid
    ON findings(secret_service, secret_valid)
    WHERE finding_type = 'secret';

-- =============================================================================
-- 2. Compliance Finding Indexes
-- =============================================================================

-- Compliance control lookup
CREATE INDEX IF NOT EXISTS idx_findings_compliance_control
    ON findings(compliance_control_id)
    WHERE compliance_control_id IS NOT NULL;

-- Compliance result filter
CREATE INDEX IF NOT EXISTS idx_findings_compliance_result
    ON findings(compliance_result)
    WHERE compliance_result IS NOT NULL;

-- =============================================================================
-- 3. Web3 Finding Indexes
-- =============================================================================

-- SWC ID lookup
CREATE INDEX IF NOT EXISTS idx_findings_web3_swc
    ON findings(web3_swc_id)
    WHERE web3_swc_id IS NOT NULL;

-- Chain + contract composite for smart contract queries
CREATE INDEX IF NOT EXISTS idx_findings_web3_chain_contract
    ON findings(web3_chain, web3_contract_address)
    WHERE finding_type = 'web3';

-- =============================================================================
-- 4. Misconfiguration Finding Indexes
-- =============================================================================

-- Resource type filter
CREATE INDEX IF NOT EXISTS idx_findings_misconfig_resource_type
    ON findings(misconfig_resource_type)
    WHERE misconfig_resource_type IS NOT NULL;

-- Resource type + policy composite for IaC queries
CREATE INDEX IF NOT EXISTS idx_findings_misconfig_type_policy
    ON findings(misconfig_resource_type, misconfig_policy_id)
    WHERE finding_type = 'misconfiguration';

-- =============================================================================
-- 5. ASVS (Application Security Verification Standard) Indexes
-- =============================================================================

-- ASVS section lookup
CREATE INDEX IF NOT EXISTS idx_findings_asvs_section
    ON findings(asvs_section)
    WHERE asvs_section IS NOT NULL;

-- ASVS control lookup
CREATE INDEX IF NOT EXISTS idx_findings_asvs_control
    ON findings(asvs_control_id)
    WHERE asvs_control_id IS NOT NULL;

-- =============================================================================
-- 6. Remediation Indexes
-- =============================================================================

-- Findings with remediation data
CREATE INDEX IF NOT EXISTS idx_findings_has_remediation
    ON findings(tenant_id)
    WHERE remediation IS NOT NULL AND remediation != '{}'::jsonb;

-- Findings with automated fix available
CREATE INDEX IF NOT EXISTS idx_findings_fix_available
    ON findings(tenant_id)
    WHERE remediation IS NOT NULL AND (remediation->>'fix_available')::boolean = true;

-- =============================================================================
-- 7. Resolution & Component Tracking
-- =============================================================================

-- Resolved by user
CREATE INDEX IF NOT EXISTS idx_findings_resolved_by
    ON findings(resolved_by)
    WHERE resolved_by IS NOT NULL;

-- Component + tenant composite for dependency-vulnerability joins
CREATE INDEX IF NOT EXISTS idx_findings_component_tenant
    ON findings(component_id, tenant_id)
    WHERE component_id IS NOT NULL;

-- =============================================================================
-- 8. Security-Critical Composite Indexes
-- =============================================================================

-- Sensitive data assets (PII or PHI exposed)
CREATE INDEX IF NOT EXISTS idx_assets_sensitive_data
    ON assets(tenant_id)
    WHERE (pii_data_exposed = true OR phi_data_exposed = true)
      AND status != 'archived';

-- High-risk internet-facing findings
CREATE INDEX IF NOT EXISTS idx_findings_high_risk_exposure
    ON findings(tenant_id)
    WHERE is_internet_accessible = true
      AND severity IN ('critical', 'high')
      AND status NOT IN ('resolved', 'false_positive');
