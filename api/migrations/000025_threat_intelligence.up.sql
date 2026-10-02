-- =============================================================================
-- Migration 025: Threat Intelligence Tables (EPSS & KEV Cache)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Cache tables for threat intelligence data from external sources:
-- - EPSS scores from FIRST.org (daily sync)
-- - KEV catalog from CISA (daily sync)

-- EPSS Scores Cache (from FIRST.org)
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id VARCHAR(30) PRIMARY KEY,
    epss_score DECIMAL(8,6) NOT NULL,
    percentile DECIMAL(8,6),
    model_version VARCHAR(20),
    score_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE epss_scores IS 'Cache of EPSS (Exploit Prediction Scoring System) scores from FIRST.org';
COMMENT ON COLUMN epss_scores.epss_score IS 'Probability of exploitation in the wild in the next 30 days (0.0 to 1.0)';
COMMENT ON COLUMN epss_scores.percentile IS 'Percentile rank compared to all other CVEs';

-- KEV Catalog Cache (from CISA Known Exploited Vulnerabilities)
CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id VARCHAR(30) PRIMARY KEY,
    vendor_project VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name TEXT NOT NULL,
    short_description TEXT,
    date_added DATE NOT NULL,
    due_date DATE,
    known_ransomware_campaign_use VARCHAR(50),
    notes TEXT,
    cwes TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE kev_catalog IS 'Cache of CISA Known Exploited Vulnerabilities catalog';
COMMENT ON COLUMN kev_catalog.known_ransomware_campaign_use IS 'Known, Unknown, or specific campaign name';

-- Threat Intel Sync Status (Tracks sync metadata for each data source)
CREATE TABLE IF NOT EXISTS threat_intel_sync_status (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_name VARCHAR(50) NOT NULL UNIQUE,
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    last_sync_error TEXT,
    records_synced INTEGER DEFAULT 0,
    sync_duration_ms INTEGER,
    next_sync_at TIMESTAMPTZ,
    sync_interval_hours INTEGER NOT NULL DEFAULT 24,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_sync_status CHECK (last_sync_status IN ('pending', 'running', 'success', 'failed'))
);

COMMENT ON TABLE threat_intel_sync_status IS 'Tracks sync status for threat intelligence data sources';

-- =============================================================================
-- Indexes
-- =============================================================================

-- EPSS indexes
CREATE INDEX IF NOT EXISTS idx_epss_scores_score ON epss_scores(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_epss_scores_percentile ON epss_scores(percentile DESC);
CREATE INDEX IF NOT EXISTS idx_epss_scores_date ON epss_scores(score_date DESC);

-- KEV indexes
CREATE INDEX IF NOT EXISTS idx_kev_catalog_date_added ON kev_catalog(date_added DESC);
CREATE INDEX IF NOT EXISTS idx_kev_catalog_due_date ON kev_catalog(due_date);
CREATE INDEX IF NOT EXISTS idx_kev_catalog_vendor ON kev_catalog(vendor_project);
CREATE INDEX IF NOT EXISTS idx_kev_catalog_ransomware ON kev_catalog(known_ransomware_campaign_use)
    WHERE known_ransomware_campaign_use IS NOT NULL AND known_ransomware_campaign_use != 'Unknown';

-- Sync status indexes
CREATE INDEX IF NOT EXISTS idx_threat_intel_sync_source ON threat_intel_sync_status(source_name);
CREATE INDEX IF NOT EXISTS idx_threat_intel_sync_enabled ON threat_intel_sync_status(is_enabled) WHERE is_enabled = TRUE;

-- =============================================================================
-- Seed Data
-- =============================================================================

INSERT INTO threat_intel_sync_status (source_name, sync_interval_hours, is_enabled, metadata) VALUES
    ('epss', 24, TRUE, '{"url": "https://epss.cyentia.com/epss_scores-current.csv.gz", "format": "csv.gz"}'),
    ('kev', 24, TRUE, '{"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "format": "json"}')
ON CONFLICT (source_name) DO NOTHING;

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_epss_scores_updated_at ON epss_scores;
CREATE TRIGGER trigger_epss_scores_updated_at
    BEFORE UPDATE ON epss_scores
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_kev_catalog_updated_at ON kev_catalog;
CREATE TRIGGER trigger_kev_catalog_updated_at
    BEFORE UPDATE ON kev_catalog
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_threat_intel_sync_updated_at ON threat_intel_sync_status;
CREATE TRIGGER trigger_threat_intel_sync_updated_at
    BEFORE UPDATE ON threat_intel_sync_status
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

