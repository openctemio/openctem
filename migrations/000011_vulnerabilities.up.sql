-- =============================================================================
-- Migration 011: Vulnerabilities (Global CVE Catalog)
-- OpenCTEM OSS Edition
-- =============================================================================

-- Vulnerabilities (Global CVE database - not tenant-scoped)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(30) UNIQUE NOT NULL,
    aliases TEXT[] DEFAULT '{}',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'unknown',
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(200),
    epss_score DECIMAL(8,6),
    epss_percentile DECIMAL(8,6),
    cisa_kev_date_added TIMESTAMPTZ,
    cisa_kev_due_date TIMESTAMPTZ,
    cisa_kev_ransomware_use VARCHAR(100),
    cisa_kev_notes TEXT,
    exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_maturity VARCHAR(20) NOT NULL DEFAULT 'none',
    reference_urls JSONB NOT NULL DEFAULT '[]',
    affected_versions JSONB NOT NULL DEFAULT '[]',
    fixed_versions TEXT[] DEFAULT '{}',
    remediation TEXT,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_vuln_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'none', 'unknown')),
    CONSTRAINT chk_vuln_exploit_maturity CHECK (exploit_maturity IN ('none', 'poc', 'functional', 'weaponized', 'unknown')),
    CONSTRAINT chk_vuln_status CHECK (status IN ('open', 'patched', 'mitigated', 'not_affected', 'investigating'))
);

COMMENT ON TABLE vulnerabilities IS 'Global CVE vulnerability database (shared across all tenants)';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss_score ON vulnerabilities(epss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_exploit_available ON vulnerabilities(exploit_available) WHERE exploit_available = TRUE;
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_exploit_maturity ON vulnerabilities(exploit_maturity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cisa_kev ON vulnerabilities(cisa_kev_date_added) WHERE cisa_kev_date_added IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_at ON vulnerabilities(published_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_aliases ON vulnerabilities USING GIN(aliases);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_created_at ON vulnerabilities(created_at DESC);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_vulnerabilities_updated_at ON vulnerabilities;
CREATE TRIGGER trigger_vulnerabilities_updated_at
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
