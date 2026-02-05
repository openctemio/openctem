-- =============================================================================
-- Migration 009: Asset Extensions (Repositories, Branches, Services)
-- OpenCTEM OSS Edition
-- =============================================================================

-- Asset Repositories Extension (for repository type assets)
CREATE TABLE IF NOT EXISTS asset_repositories (
    asset_id UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    repo_id VARCHAR(255),
    full_name VARCHAR(500),
    scm_organization VARCHAR(255),
    clone_url VARCHAR(1000),
    web_url VARCHAR(1000),
    ssh_url VARCHAR(1000),
    default_branch VARCHAR(100) DEFAULT 'main',
    visibility VARCHAR(20) NOT NULL DEFAULT 'private',
    language VARCHAR(50),
    languages JSONB DEFAULT '{}',
    topics TEXT[] DEFAULT '{}',
    stars INTEGER NOT NULL DEFAULT 0,
    forks INTEGER NOT NULL DEFAULT 0,
    watchers INTEGER NOT NULL DEFAULT 0,
    open_issues INTEGER NOT NULL DEFAULT 0,
    contributors_count INTEGER NOT NULL DEFAULT 0,
    size_kb INTEGER NOT NULL DEFAULT 0,
    risk_score DECIMAL(4,2) NOT NULL DEFAULT 0.0,
    scan_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    scan_schedule VARCHAR(50),
    last_scanned_at TIMESTAMPTZ,
    branch_count INTEGER NOT NULL DEFAULT 0,
    protected_branch_count INTEGER NOT NULL DEFAULT 0,
    component_count INTEGER NOT NULL DEFAULT 0,
    vulnerable_component_count INTEGER NOT NULL DEFAULT 0,
    repo_created_at TIMESTAMPTZ,
    repo_updated_at TIMESTAMPTZ,
    repo_pushed_at TIMESTAMPTZ,

    CONSTRAINT chk_repo_visibility CHECK (visibility IN ('public', 'private', 'internal'))
);

COMMENT ON TABLE asset_repositories IS 'Extended fields for repository-type assets';

-- Repository Branches (Git branches - only for repository assets)
-- Note: References asset_repositories(asset_id) to enforce that only repos can have branches
CREATE TABLE IF NOT EXISTS repository_branches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES asset_repositories(asset_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    branch_type VARCHAR(20) NOT NULL DEFAULT 'other',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_protected BOOLEAN NOT NULL DEFAULT FALSE,
    last_commit_sha VARCHAR(64),
    last_commit_message TEXT,
    last_commit_author VARCHAR(255),
    last_commit_author_avatar VARCHAR(500),
    last_commit_at TIMESTAMPTZ,
    scan_on_push BOOLEAN NOT NULL DEFAULT TRUE,
    scan_on_pr BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan_id UUID,
    last_scanned_at TIMESTAMPTZ,
    scan_status VARCHAR(20) NOT NULL DEFAULT 'not_scanned',
    quality_gate_status VARCHAR(20) NOT NULL DEFAULT 'not_computed',
    findings_total INTEGER NOT NULL DEFAULT 0,
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high INTEGER NOT NULL DEFAULT 0,
    findings_medium INTEGER NOT NULL DEFAULT 0,
    findings_low INTEGER NOT NULL DEFAULT 0,
    keep_when_inactive BOOLEAN NOT NULL DEFAULT TRUE,
    retention_days INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_repo_branch_type CHECK (branch_type IN ('main', 'develop', 'feature', 'release', 'hotfix', 'other')),
    CONSTRAINT chk_repo_branch_scan_status CHECK (scan_status IN ('passed', 'failed', 'warning', 'scanning', 'not_scanned')),
    CONSTRAINT chk_repo_branch_quality_gate CHECK (quality_gate_status IN ('passed', 'failed', 'warning', 'not_computed')),
    CONSTRAINT unique_repository_branch UNIQUE (repository_id, name)
);

COMMENT ON TABLE repository_branches IS 'Git branches for repository assets';

-- Asset Services (Open ports/services on assets)
CREATE TABLE IF NOT EXISTS asset_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
    name VARCHAR(100),
    service_type VARCHAR(50) NOT NULL DEFAULT 'other',
    product VARCHAR(255),
    version VARCHAR(100),
    banner TEXT,
    cpe VARCHAR(500),

    -- Exposure (CTEM)
    is_public BOOLEAN DEFAULT false,
    exposure VARCHAR(50) DEFAULT 'private',
    tls_enabled BOOLEAN DEFAULT false,
    tls_version VARCHAR(20),

    -- Discovery
    discovery_source VARCHAR(100),
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),

    -- Risk
    finding_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,

    -- State
    state VARCHAR(20) NOT NULL DEFAULT 'active',
    state_changed_at TIMESTAMPTZ,

    confidence INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_service_protocol CHECK (protocol IN ('tcp', 'udp', 'sctp')),
    CONSTRAINT chk_service_type CHECK (service_type IN (
        'http', 'https', 'ssh', 'ftp', 'sftp', 'smtp', 'smtps', 'dns',
        'mysql', 'postgresql', 'mongodb', 'redis', 'rdp', 'smb', 'ldap',
        'kerberos', 'grpc', 'telnet', 'vnc', 'imap', 'imaps', 'pop3', 'pop3s',
        'ntp', 'snmp', 'rtsp', 'sip', 'elasticsearch', 'memcached', 'mssql',
        'oracle', 'cassandra', 'kafka', 'rabbitmq', 'kubernetes', 'docker', 'other'
    )),
    CONSTRAINT chk_service_state CHECK (state IN ('active', 'inactive', 'filtered', 'open', 'closed', 'unknown')),
    CONSTRAINT chk_service_exposure CHECK (exposure IN ('public', 'restricted', 'private')),
    CONSTRAINT chk_service_port CHECK (port > 0 AND port <= 65535),
    CONSTRAINT chk_service_risk_score CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT unique_asset_service UNIQUE (asset_id, port, protocol)
);

COMMENT ON TABLE asset_services IS 'Open ports and services discovered on assets';
COMMENT ON COLUMN asset_services.service_type IS 'Service type for categorization';
COMMENT ON COLUMN asset_services.is_public IS 'CTEM: Whether service is publicly accessible';
COMMENT ON COLUMN asset_services.exposure IS 'CTEM: Exposure level (public, restricted, private)';
COMMENT ON COLUMN asset_services.cpe IS 'Common Platform Enumeration identifier';

-- Asset State History (Track asset state changes for CTEM audit)
CREATE TABLE IF NOT EXISTS asset_state_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- Change details
    change_type VARCHAR(50) NOT NULL,
    field VARCHAR(100),
    old_value TEXT,
    new_value TEXT,

    -- Context
    reason TEXT,
    metadata JSONB DEFAULT '{}',
    source VARCHAR(50),  -- scan, manual, integration, system

    -- Audit
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    changed_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_change_type CHECK (change_type IN (
        'appeared', 'disappeared', 'recovered',
        'exposure_changed', 'status_changed',
        'criticality_changed', 'owner_changed', 'compliance_changed',
        'classification_changed', 'internet_exposure_changed'
    )),
    CONSTRAINT chk_state_history_source CHECK (source IS NULL OR source IN (
        'scan', 'manual', 'integration', 'system', 'agent', 'api'
    ))
);

COMMENT ON TABLE asset_state_history IS 'Track asset state changes for shadow IT detection and audit';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Repository indexes
CREATE INDEX IF NOT EXISTS idx_asset_repos_repo_id ON asset_repositories(repo_id);
CREATE INDEX IF NOT EXISTS idx_asset_repos_full_name ON asset_repositories(full_name);
CREATE INDEX IF NOT EXISTS idx_asset_repos_scm_org ON asset_repositories(scm_organization);
CREATE INDEX IF NOT EXISTS idx_asset_repos_language ON asset_repositories(language);
CREATE INDEX IF NOT EXISTS idx_asset_repos_visibility ON asset_repositories(visibility);
CREATE INDEX IF NOT EXISTS idx_asset_repos_risk_score ON asset_repositories(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_asset_repos_last_scanned ON asset_repositories(last_scanned_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_asset_repos_topics ON asset_repositories USING GIN(topics);
CREATE INDEX IF NOT EXISTS idx_asset_repos_languages ON asset_repositories USING GIN(languages);

-- Repository branch indexes
CREATE INDEX IF NOT EXISTS idx_repository_branches_repository_id ON repository_branches(repository_id);
CREATE INDEX IF NOT EXISTS idx_repository_branches_name ON repository_branches(name);
CREATE INDEX IF NOT EXISTS idx_repository_branches_is_default ON repository_branches(repository_id) WHERE is_default = TRUE;
CREATE INDEX IF NOT EXISTS idx_repository_branches_scan_status ON repository_branches(scan_status);
CREATE INDEX IF NOT EXISTS idx_repository_branches_last_scanned ON repository_branches(last_scanned_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_repository_branches_created_at ON repository_branches(created_at DESC);

-- Service indexes
CREATE INDEX IF NOT EXISTS idx_asset_services_tenant ON asset_services(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_services_asset ON asset_services(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_services_port ON asset_services(port);
CREATE INDEX IF NOT EXISTS idx_asset_services_state ON asset_services(state);
CREATE INDEX IF NOT EXISTS idx_asset_services_type ON asset_services(service_type);
CREATE INDEX IF NOT EXISTS idx_asset_services_product ON asset_services(product) WHERE product IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_services_public ON asset_services(tenant_id) WHERE is_public = true;
CREATE INDEX IF NOT EXISTS idx_asset_services_last_seen ON asset_services(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_asset_services_risk ON asset_services(risk_score DESC) WHERE risk_score > 0;
CREATE INDEX IF NOT EXISTS idx_asset_services_tenant_type ON asset_services(tenant_id, service_type);
CREATE INDEX IF NOT EXISTS idx_asset_services_active_public ON asset_services(tenant_id, asset_id)
    WHERE state = 'active' AND is_public = true;
CREATE INDEX IF NOT EXISTS idx_asset_services_with_findings ON asset_services(tenant_id, finding_count DESC)
    WHERE finding_count > 0;

-- Asset state history indexes
CREATE INDEX IF NOT EXISTS idx_asset_state_history_tenant ON asset_state_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_state_history_asset ON asset_state_history(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_state_history_type ON asset_state_history(change_type);
CREATE INDEX IF NOT EXISTS idx_asset_state_history_time ON asset_state_history(changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_state_history_source ON asset_state_history(source) WHERE source IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_state_history_tenant_time ON asset_state_history(tenant_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_state_history_asset_time ON asset_state_history(asset_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_state_appeared ON asset_state_history(tenant_id, changed_at DESC)
    WHERE change_type IN ('appeared', 'disappeared', 'recovered');
CREATE INDEX IF NOT EXISTS idx_asset_state_exposure ON asset_state_history(tenant_id, changed_at DESC)
    WHERE change_type IN ('exposure_changed', 'internet_exposure_changed');
CREATE INDEX IF NOT EXISTS idx_asset_state_compliance ON asset_state_history(tenant_id, changed_at DESC)
    WHERE change_type IN ('compliance_changed', 'classification_changed', 'owner_changed');

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_repository_branches_updated_at ON repository_branches;
CREATE TRIGGER trigger_repository_branches_updated_at
    BEFORE UPDATE ON repository_branches
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_asset_services_updated_at ON asset_services;
CREATE TRIGGER trigger_asset_services_updated_at
    BEFORE UPDATE ON asset_services
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
