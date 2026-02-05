-- =============================================================================
-- Migration 000029: Scanner Templates
-- =============================================================================
-- Custom templates for scanners (Nuclei, Semgrep, Gitleaks).
-- Supports both inline content and external sources.
-- =============================================================================

-- =============================================================================
-- Template Sources
-- =============================================================================

CREATE TABLE IF NOT EXISTS template_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant Isolation
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Source Configuration
    source_type VARCHAR(20) NOT NULL,               -- git, s3, http
    template_type VARCHAR(20) NOT NULL,             -- nuclei, semgrep, gitleaks

    -- Source-specific Configuration
    git_config JSONB,                               -- {url, branch, path, auth_type}
    s3_config JSONB,                                -- {bucket, region, prefix, endpoint}
    http_config JSONB,                              -- {url, auth_type, headers}

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Sync Settings
    auto_sync_on_scan BOOLEAN NOT NULL DEFAULT TRUE,
    cache_ttl_minutes INTEGER NOT NULL DEFAULT 60,

    -- Sync Status
    last_sync_at TIMESTAMPTZ,
    last_sync_hash VARCHAR(64),                     -- ETag/commit for change detection
    last_sync_status VARCHAR(20) DEFAULT 'pending',
    last_sync_error TEXT,

    -- Statistics
    total_templates INTEGER NOT NULL DEFAULT 0,
    last_sync_count INTEGER NOT NULL DEFAULT 0,

    -- Credential Reference
    credential_id UUID,                             -- Reference to credentials table

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_template_source_type CHECK (source_type IN ('git', 's3', 'http')),
    CONSTRAINT chk_template_type CHECK (template_type IN ('nuclei', 'semgrep', 'gitleaks')),
    CONSTRAINT chk_sync_status CHECK (last_sync_status IN ('pending', 'in_progress', 'success', 'failed')),
    CONSTRAINT unique_template_source_name UNIQUE (tenant_id, name)
);

-- =============================================================================
-- Scanner Templates
-- =============================================================================

CREATE TABLE IF NOT EXISTS scanner_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant Isolation
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Source Reference (NULL = manual upload)
    source_id UUID REFERENCES template_sources(id) ON DELETE SET NULL,

    -- Template Identification
    name VARCHAR(255) NOT NULL,
    template_type VARCHAR(20) NOT NULL,             -- nuclei, semgrep, gitleaks
    version VARCHAR(50) DEFAULT '1.0.0',

    -- Content Storage
    content BYTEA,                                  -- Inline content (< 1MB)
    content_url VARCHAR(500),                       -- S3/external URL (> 1MB)
    content_hash VARCHAR(64) NOT NULL,              -- SHA-256 hash
    signature_hash VARCHAR(64),                     -- HMAC-SHA256 for verification

    -- Metadata
    rule_count INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',

    -- Status
    status VARCHAR(20) DEFAULT 'active',
    validation_error TEXT,

    -- Source Tracking
    sync_source VARCHAR(20) DEFAULT 'manual',
    source_path VARCHAR(500),                       -- Path within source
    source_commit VARCHAR(64),                      -- Git commit hash

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_scanner_template_type CHECK (template_type IN ('nuclei', 'semgrep', 'gitleaks')),
    CONSTRAINT chk_scanner_template_status CHECK (status IN ('active', 'pending_review', 'deprecated', 'revoked')),
    CONSTRAINT chk_sync_source CHECK (sync_source IN ('manual', 'git', 's3', 'http')),
    CONSTRAINT unique_scanner_template UNIQUE (tenant_id, template_type, name)
);

-- =============================================================================
-- Scan Profile Template Sources Link
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_profile_template_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_profile_id UUID NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES template_sources(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_profile_source UNIQUE (scan_profile_id, source_id)
);

-- =============================================================================
-- Indexes for template_sources
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_template_sources_tenant ON template_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_template_sources_type ON template_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_template_sources_template_type ON template_sources(template_type);
CREATE INDEX IF NOT EXISTS idx_template_sources_enabled ON template_sources(enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_template_sources_needs_sync ON template_sources(tenant_id, last_sync_at)
    WHERE enabled = TRUE AND auto_sync_on_scan = TRUE;

-- =============================================================================
-- Indexes for scanner_templates
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_scanner_templates_tenant ON scanner_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_type ON scanner_templates(template_type);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_status ON scanner_templates(status);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_source ON scanner_templates(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scanner_templates_tags ON scanner_templates USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_scanner_templates_hash ON scanner_templates(content_hash);

-- Full-text search
CREATE INDEX IF NOT EXISTS idx_scanner_templates_search ON scanner_templates
    USING GIN(to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));

-- =============================================================================
-- Indexes for scan_profile_template_sources
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_spts_profile ON scan_profile_template_sources(scan_profile_id);
CREATE INDEX IF NOT EXISTS idx_spts_source ON scan_profile_template_sources(source_id);

-- =============================================================================
-- Triggers
-- =============================================================================

CREATE TRIGGER update_template_sources_updated_at
    BEFORE UPDATE ON template_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scanner_templates_updated_at
    BEFORE UPDATE ON scanner_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Comments
-- =============================================================================

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
