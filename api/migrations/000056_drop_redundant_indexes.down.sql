-- =============================================================================
-- Migration 000056 DOWN: Recreate Dropped Redundant Indexes
-- =============================================================================

-- Findings single-column indexes
CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_tool_name ON findings(tool_name);
CREATE INDEX IF NOT EXISTS idx_findings_finding_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset_status ON findings(asset_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_secret_service ON findings(secret_service) WHERE finding_type = 'secret';
CREATE INDEX IF NOT EXISTS idx_findings_web3_chain ON findings(web3_chain) WHERE finding_type = 'web3';
CREATE INDEX IF NOT EXISTS idx_findings_compliance_framework ON findings(compliance_framework) WHERE finding_type = 'compliance';

-- Assets single-column indexes
CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);
CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_assets_data_classification ON assets(data_classification) WHERE data_classification IS NOT NULL;
