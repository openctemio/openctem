-- =============================================================================
-- Migration 029: Finding Data Flows + Scanner Templates
-- OpenCTEM OSS Edition
-- =============================================================================

-- =============================================================================
-- Part 1: Finding Data Flows (SARIF codeFlows)
-- =============================================================================
-- Purpose: Enable queryable taint tracking paths from source to sink
-- Use case: Attack path analysis, data flow queries across files/functions

-- Finding Data Flows: Container for code flow paths
-- Maps to SARIF codeFlows array - each finding can have multiple data flow traces
CREATE TABLE IF NOT EXISTS finding_data_flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    flow_index INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    importance VARCHAR(20) DEFAULT 'essential',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_flow_importance CHECK (importance IN ('essential', 'important', 'unimportant')),
    CONSTRAINT uq_finding_data_flow UNIQUE (finding_id, flow_index)
);

COMMENT ON TABLE finding_data_flows IS 'SARIF codeFlows - taint tracking paths from source to sink';
COMMENT ON COLUMN finding_data_flows.flow_index IS 'Order of this flow within the finding (0-based)';
COMMENT ON COLUMN finding_data_flows.importance IS 'SARIF threadFlowImportance: essential, important, unimportant';

-- Finding Flow Locations: Individual steps in a data flow
-- Maps to SARIF threadFlowLocation - each step in the taint path
CREATE TABLE IF NOT EXISTS finding_flow_locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_flow_id UUID NOT NULL REFERENCES finding_data_flows(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    location_type VARCHAR(20) NOT NULL DEFAULT 'intermediate',

    -- Physical location (file/line/column)
    file_path VARCHAR(1000),
    start_line INTEGER,
    end_line INTEGER,
    start_column INTEGER,
    end_column INTEGER,
    snippet TEXT,

    -- Logical location (function/class/module context)
    function_name VARCHAR(500),
    class_name VARCHAR(500),
    fully_qualified_name VARCHAR(1000),
    module_name VARCHAR(500),

    -- Context
    label VARCHAR(500),
    message TEXT,
    nesting_level INTEGER DEFAULT 0,

    -- Step importance (SARIF importance enum)
    importance VARCHAR(20) DEFAULT 'essential',

    CONSTRAINT chk_flow_location_type CHECK (location_type IN ('source', 'intermediate', 'sink', 'sanitizer')),
    CONSTRAINT chk_location_importance CHECK (importance IN ('essential', 'important', 'unimportant'))
);

COMMENT ON TABLE finding_flow_locations IS 'Individual steps in a data flow trace (source -> intermediate -> sink)';
COMMENT ON COLUMN finding_flow_locations.location_type IS 'Role in flow: source (taint origin), intermediate (propagation), sink (vulnerable use), sanitizer (safe path)';
COMMENT ON COLUMN finding_flow_locations.label IS 'Variable/expression name being tracked through the flow';
COMMENT ON COLUMN finding_flow_locations.nesting_level IS 'SARIF nestingLevel for display indentation';

-- Indexes for finding data flows
CREATE INDEX IF NOT EXISTS idx_data_flows_finding ON finding_data_flows(finding_id);
CREATE INDEX IF NOT EXISTS idx_flow_locations_flow_step ON finding_flow_locations(data_flow_id, step_index);
CREATE INDEX IF NOT EXISTS idx_flow_locations_file ON finding_flow_locations(file_path) WHERE file_path IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_flow_locations_function ON finding_flow_locations(function_name) WHERE function_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_flow_locations_class ON finding_flow_locations(class_name) WHERE class_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_flow_locations_type ON finding_flow_locations(location_type);
CREATE INDEX IF NOT EXISTS idx_flow_locations_file_line ON finding_flow_locations(file_path, start_line) WHERE file_path IS NOT NULL;

-- =============================================================================
-- Part 2: Scanner Templates
-- =============================================================================
-- Custom templates for scanners (Nuclei, Semgrep, Gitleaks).
-- Supports both inline content and external sources.

-- Template Sources
CREATE TABLE IF NOT EXISTS template_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source_type VARCHAR(20) NOT NULL,
    template_type VARCHAR(20) NOT NULL,
    git_config JSONB,
    s3_config JSONB,
    http_config JSONB,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    auto_sync_on_scan BOOLEAN NOT NULL DEFAULT TRUE,
    cache_ttl_minutes INTEGER NOT NULL DEFAULT 60,
    last_sync_at TIMESTAMPTZ,
    last_sync_hash VARCHAR(64),
    last_sync_status VARCHAR(20) DEFAULT 'pending',
    last_sync_error TEXT,
    total_templates INTEGER NOT NULL DEFAULT 0,
    last_sync_count INTEGER NOT NULL DEFAULT 0,
    credential_id UUID,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_template_source_type CHECK (source_type IN ('git', 's3', 'http')),
    CONSTRAINT chk_template_type CHECK (template_type IN ('nuclei', 'semgrep', 'gitleaks')),
    CONSTRAINT chk_sync_status CHECK (last_sync_status IN ('pending', 'in_progress', 'success', 'failed')),
    CONSTRAINT unique_template_source_name UNIQUE (tenant_id, name)
);

-- Scanner Templates
CREATE TABLE IF NOT EXISTS scanner_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id UUID REFERENCES template_sources(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    template_type VARCHAR(20) NOT NULL,
    version VARCHAR(50) DEFAULT '1.0.0',
    content BYTEA,
    content_url VARCHAR(500),
    content_hash VARCHAR(64) NOT NULL,
    signature_hash VARCHAR(64),
    rule_count INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'active',
    validation_error TEXT,
    sync_source VARCHAR(20) DEFAULT 'manual',
    source_path VARCHAR(500),
    source_commit VARCHAR(64),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_scanner_template_type CHECK (template_type IN ('nuclei', 'semgrep', 'gitleaks')),
    CONSTRAINT chk_scanner_template_status CHECK (status IN ('active', 'pending_review', 'deprecated', 'revoked')),
    CONSTRAINT chk_sync_source CHECK (sync_source IN ('manual', 'git', 's3', 'http')),
    CONSTRAINT unique_scanner_template UNIQUE (tenant_id, template_type, name)
);

-- Scan Profile Template Sources Link
CREATE TABLE IF NOT EXISTS scan_profile_template_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_profile_id UUID NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES template_sources(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_profile_source UNIQUE (scan_profile_id, source_id)
);

-- Indexes for template_sources
CREATE INDEX IF NOT EXISTS idx_template_sources_tenant ON template_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_template_sources_type ON template_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_template_sources_template_type ON template_sources(template_type);
CREATE INDEX IF NOT EXISTS idx_template_sources_enabled ON template_sources(enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_template_sources_needs_sync ON template_sources(tenant_id, last_sync_at)
    WHERE enabled = TRUE AND auto_sync_on_scan = TRUE;

-- Indexes for scanner_templates
CREATE INDEX IF NOT EXISTS idx_scanner_templates_tenant ON scanner_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_type ON scanner_templates(template_type);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_status ON scanner_templates(status);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_source ON scanner_templates(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scanner_templates_tags ON scanner_templates USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_hash ON scanner_templates(content_hash);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_search ON scanner_templates
    USING GIN(to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));

-- Indexes for scan_profile_template_sources
CREATE INDEX IF NOT EXISTS idx_spts_profile ON scan_profile_template_sources(scan_profile_id);
CREATE INDEX IF NOT EXISTS idx_spts_source ON scan_profile_template_sources(source_id);

-- Triggers
CREATE TRIGGER update_template_sources_updated_at
    BEFORE UPDATE ON template_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scanner_templates_updated_at
    BEFORE UPDATE ON scanner_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE template_sources IS 'External sources for scanner templates (Git, S3, HTTP)';
COMMENT ON COLUMN template_sources.source_type IS 'Source type: git, s3, http';
COMMENT ON COLUMN template_sources.template_type IS 'Scanner type: nuclei, semgrep, gitleaks';
COMMENT ON COLUMN template_sources.auto_sync_on_scan IS 'If true, sync templates before each scan';

COMMENT ON TABLE scanner_templates IS 'Custom scanner templates (Nuclei, Semgrep, Gitleaks)';
COMMENT ON COLUMN scanner_templates.content IS 'Inline template content (for small templates)';
COMMENT ON COLUMN scanner_templates.content_url IS 'External URL for large templates';
COMMENT ON COLUMN scanner_templates.content_hash IS 'SHA-256 hash for integrity verification';
COMMENT ON COLUMN scanner_templates.sync_source IS 'How template was added: manual, git, s3, http';

COMMENT ON TABLE scan_profile_template_sources IS 'Links scan profiles to template sources';
