-- =============================================================================
-- Migration 012: Findings
-- OpenCTEM OSS Edition
-- =============================================================================
-- Combined findings table with all features:
-- - Base fields from core findings
-- - CTEM fields for exposure/remediation tracking
-- - SARIF 2.1.0 fields for scanner compatibility
-- - Type-specific fields (secret, compliance, web3, misconfiguration)
-- - ASVS fields for secure coding standards
-- Note: SLA fields removed (enterprise feature)
-- =============================================================================

-- Findings (Vulnerability instances in assets)
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    branch_id UUID REFERENCES repository_branches(id) ON DELETE SET NULL,
    component_id UUID REFERENCES asset_components(id) ON DELETE SET NULL,

    -- Source & Tool Info
    source VARCHAR(20) NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    tool_version VARCHAR(50),
    rule_id VARCHAR(255),
    rule_name VARCHAR(500),
    agent_id UUID,

    -- Finding Type Discriminator
    finding_type VARCHAR(20) DEFAULT 'vulnerability',

    -- Location Info
    file_path VARCHAR(1000),
    start_line INTEGER,
    end_line INTEGER,
    start_column INTEGER,
    end_column INTEGER,
    snippet TEXT,
    context_snippet TEXT,
    context_start_line INTEGER,

    -- Finding Details
    title VARCHAR(500),
    message TEXT NOT NULL,
    description TEXT,
    remediation JSONB,

    -- Classification & Risk
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    cve_id VARCHAR(20),
    tags TEXT[] DEFAULT '{}',

    -- Status & Lifecycle (Unified workflow)
    status VARCHAR(30) NOT NULL DEFAULT 'new',
    resolution TEXT,
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acceptance_expires_at TIMESTAMPTZ,

    -- Scan Info
    scan_id VARCHAR(100),
    fingerprint VARCHAR(64) NOT NULL,

    -- Assignment
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    verified_at TIMESTAMPTZ,
    verified_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Detection History
    first_detected_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    first_detected_branch VARCHAR(255),
    first_detected_commit VARCHAR(64),
    last_seen_branch VARCHAR(255),
    last_seen_commit VARCHAR(64),

    -- Classification
    cwe_ids TEXT[] DEFAULT '{}',
    owasp_ids TEXT[] DEFAULT '{}',

    -- External References
    related_issue_url VARCHAR(1000),
    related_pr_url VARCHAR(1000),

    -- Duplicate Tracking
    duplicate_of UUID REFERENCES findings(id) ON DELETE SET NULL,
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    comments_count INTEGER NOT NULL DEFAULT 0,

    -- ==========================================================================
    -- CTEM Fields (Exposure & Remediation Context)
    -- ==========================================================================

    -- Exposure Vector
    exposure_vector VARCHAR(50) DEFAULT 'unknown',
    is_network_accessible BOOLEAN DEFAULT false,
    is_internet_accessible BOOLEAN DEFAULT false,
    attack_prerequisites TEXT,

    -- Remediation Context
    remediation_type VARCHAR(50),
    estimated_fix_time INTEGER,  -- minutes
    fix_complexity VARCHAR(20),
    remedy_available BOOLEAN DEFAULT true,

    -- Business Impact
    data_exposure_risk VARCHAR(20) DEFAULT 'none',
    reputational_impact BOOLEAN DEFAULT false,
    compliance_impact TEXT[],

    -- ==========================================================================
    -- SARIF 2.1.0 Fields (Scanner Compatibility)
    -- ==========================================================================

    -- Risk Assessment (from SAST tools)
    confidence INTEGER,
    impact VARCHAR(20),
    likelihood VARCHAR(20),

    -- Classification
    vulnerability_class TEXT[],
    subcategory TEXT[],

    -- SARIF Core
    baseline_state VARCHAR(20),
    kind VARCHAR(20),
    rank NUMERIC(5,2),
    occurrence_count INTEGER DEFAULT 1,
    correlation_id VARCHAR(100),

    -- SARIF Extended (JSONB for flexibility)
    partial_fingerprints JSONB DEFAULT '{}'::jsonb,
    related_locations JSONB DEFAULT '[]'::jsonb,
    stacks JSONB DEFAULT '[]'::jsonb,
    attachments JSONB DEFAULT '[]'::jsonb,
    work_item_uris TEXT[],
    hosted_viewer_uri VARCHAR(2000),

    -- ==========================================================================
    -- Secret-Specific Fields
    -- ==========================================================================
    secret_type VARCHAR(50),
    secret_service VARCHAR(100),
    secret_valid BOOLEAN,
    secret_revoked BOOLEAN,
    secret_entropy DECIMAL(5,2),
    secret_expires_at TIMESTAMPTZ,

    -- ==========================================================================
    -- Compliance-Specific Fields
    -- ==========================================================================
    compliance_framework VARCHAR(50),
    compliance_control_id VARCHAR(100),
    compliance_control_name VARCHAR(500),
    compliance_result VARCHAR(20),
    compliance_section VARCHAR(100),

    -- ==========================================================================
    -- Web3/Blockchain Fields
    -- ==========================================================================
    web3_chain VARCHAR(50),
    web3_chain_id BIGINT,
    web3_contract_address VARCHAR(66),
    web3_swc_id VARCHAR(20),
    web3_function_signature VARCHAR(500),
    web3_tx_hash VARCHAR(66),

    -- ==========================================================================
    -- Misconfiguration Fields
    -- ==========================================================================
    misconfig_policy_id VARCHAR(100),
    misconfig_resource_type VARCHAR(200),
    misconfig_resource_name VARCHAR(500),
    misconfig_resource_path VARCHAR(1000),
    misconfig_expected TEXT,
    misconfig_actual TEXT,

    -- ==========================================================================
    -- ASVS Fields (Application Security Verification Standard)
    -- ==========================================================================
    asvs_section VARCHAR(200),
    asvs_control_id VARCHAR(50),
    asvs_control_url VARCHAR(500),
    asvs_level INTEGER,

    -- Metadata & Timestamps
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ==========================================================================
    -- Constraints
    -- ==========================================================================

    -- Base constraints
    CONSTRAINT chk_findings_source CHECK (source IN (
        'sast', 'dast', 'sca', 'secret', 'iac', 'container',
        'cspm', 'easm', 'rasp', 'waf', 'siem',
        'manual', 'pentest', 'bug_bounty', 'red_team',
        'external', 'threat_intel', 'vendor', 'sarif', 'sca_tool', 'api'
    )),
    CONSTRAINT chk_findings_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')),
    CONSTRAINT chk_findings_status CHECK (status IN ('new', 'confirmed', 'in_progress', 'resolved', 'false_positive', 'accepted', 'duplicate')),
    CONSTRAINT chk_finding_type CHECK (finding_type IS NULL OR finding_type IN ('vulnerability', 'secret', 'misconfiguration', 'compliance', 'web3')),
    CONSTRAINT chk_findings_cvss_score CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),

    -- CTEM constraints
    CONSTRAINT chk_exposure_vector CHECK (exposure_vector IN ('network', 'local', 'physical', 'adjacent_net', 'unknown')),
    CONSTRAINT chk_remediation_type CHECK (remediation_type IS NULL OR remediation_type IN ('patch', 'upgrade', 'workaround', 'config_change', 'mitigate', 'accept_risk')),
    CONSTRAINT chk_fix_complexity CHECK (fix_complexity IS NULL OR fix_complexity IN ('simple', 'moderate', 'complex')),
    CONSTRAINT chk_data_exposure_risk CHECK (data_exposure_risk IN ('none', 'low', 'medium', 'high', 'critical')),

    -- SARIF constraints
    CONSTRAINT chk_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
    CONSTRAINT chk_impact CHECK (impact IS NULL OR impact IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT chk_likelihood CHECK (likelihood IS NULL OR likelihood IN ('high', 'medium', 'low')),
    CONSTRAINT chk_baseline_state CHECK (baseline_state IS NULL OR baseline_state IN ('new', 'unchanged', 'updated', 'absent')),
    CONSTRAINT chk_kind CHECK (kind IS NULL OR kind IN ('not_applicable', 'pass', 'fail', 'review', 'open', 'informational')),
    CONSTRAINT chk_rank CHECK (rank IS NULL OR (rank >= 0 AND rank <= 100)),

    -- Compliance constraints
    CONSTRAINT chk_compliance_result CHECK (compliance_result IS NULL OR compliance_result IN ('pass', 'fail', 'manual', 'not_applicable', 'error', 'unknown')),

    -- ASVS constraint
    CONSTRAINT chk_asvs_level CHECK (asvs_level IS NULL OR asvs_level IN (1, 2, 3))
);

COMMENT ON TABLE findings IS 'Security findings (vulnerability instances) with CTEM, SARIF, and multi-type support';
COMMENT ON COLUMN findings.status IS 'Unified workflow: new → confirmed → in_progress → resolved (or false_positive, accepted, duplicate)';
COMMENT ON COLUMN findings.finding_type IS 'Type discriminator: vulnerability, secret, misconfiguration, compliance, web3';
COMMENT ON COLUMN findings.exposure_vector IS 'CTEM: How the vulnerability can be reached (network, local, physical, adjacent_net)';
COMMENT ON COLUMN findings.is_internet_accessible IS 'CTEM: True if finding is on internet-facing asset';
COMMENT ON COLUMN findings.remediation_type IS 'CTEM: Recommended fix type (patch, upgrade, workaround, etc.)';
COMMENT ON COLUMN findings.remediation IS 'Consolidated remediation info: recommendation, fix_code, fix_regex, steps, references';
COMMENT ON COLUMN findings.confidence IS 'SARIF: Confidence score 0-100 (probability of true positive)';
COMMENT ON COLUMN findings.baseline_state IS 'SARIF: Change state (new, unchanged, updated, absent)';
COMMENT ON COLUMN findings.correlation_id IS 'SARIF: Groups logically identical results across scans';
COMMENT ON COLUMN findings.acceptance_expires_at IS 'When risk acceptance expires (requires re-review)';

-- Finding Comments
CREATE TABLE IF NOT EXISTS finding_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    is_status_change BOOLEAN NOT NULL DEFAULT FALSE,
    old_status VARCHAR(30),
    new_status VARCHAR(30),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE finding_comments IS 'Comments and status change history for findings';

-- Finding Activities (Audit trail)
CREATE TABLE IF NOT EXISTS finding_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    activity_type VARCHAR(30) NOT NULL,
    actor_type VARCHAR(20) NOT NULL DEFAULT 'user',
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_name VARCHAR(255),
    changes JSONB DEFAULT '{}',
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_activity_type CHECK (activity_type IN (
        'created', 'status_changed', 'severity_changed', 'assigned', 'unassigned',
        'comment_added', 'scan_detected', 'auto_resolved', 'auto_reopened',
        'duplicate_marked', 'duplicate_unmarked', 'accepted', 'acceptance_expired',
        'verified', 'remediation_updated', 'metadata_updated'
    )),
    CONSTRAINT chk_actor_type CHECK (actor_type IN ('user', 'system', 'scanner', 'integration', 'ai'))
);

COMMENT ON TABLE finding_activities IS 'Append-only audit trail for finding lifecycle';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Core indexes
CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_vulnerability_id ON findings(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_branch_id ON findings(branch_id);
CREATE INDEX IF NOT EXISTS idx_findings_component_id ON findings(component_id);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_tool_name ON findings(tool_name);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_finding_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_assigned_to ON findings(assigned_to);
CREATE INDEX IF NOT EXISTS idx_findings_first_detected ON findings(first_detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_cwe_ids ON findings USING GIN(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_findings_owasp_ids ON findings USING GIN(owasp_ids);
CREATE INDEX IF NOT EXISTS idx_findings_tags ON findings USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_findings_metadata ON findings USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_resolved_at ON findings(resolved_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_findings_title ON findings USING GIN(to_tsvector('english', COALESCE(title, '')));

-- Composite indexes for common queries
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_fingerprint ON findings(tenant_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_asset ON findings(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status ON findings(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity ON findings(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_type ON findings(tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_asset_status ON findings(asset_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_asset_severity ON findings(asset_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_asset_status ON findings(tenant_id, asset_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_open_severity ON findings(tenant_id, severity) WHERE status IN ('new', 'confirmed', 'in_progress');

-- Acceptance expiration index
CREATE INDEX IF NOT EXISTS idx_findings_acceptance_expires ON findings(acceptance_expires_at)
    WHERE status = 'accepted' AND acceptance_expires_at IS NOT NULL;

-- CTEM indexes
CREATE INDEX IF NOT EXISTS idx_findings_exposure_vector ON findings(exposure_vector);
CREATE INDEX IF NOT EXISTS idx_findings_network_exposed ON findings(tenant_id)
    WHERE is_network_accessible = true AND status IN ('new', 'confirmed', 'in_progress');
CREATE INDEX IF NOT EXISTS idx_findings_internet_exposed ON findings(tenant_id)
    WHERE is_internet_accessible = true AND status IN ('new', 'confirmed', 'in_progress');
CREATE INDEX IF NOT EXISTS idx_findings_remediation ON findings(remediation_type, fix_complexity)
    WHERE remediation_type IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_compliance ON findings USING GIN (compliance_impact)
    WHERE compliance_impact IS NOT NULL AND array_length(compliance_impact, 1) > 0;
CREATE INDEX IF NOT EXISTS idx_findings_data_exposure ON findings(data_exposure_risk)
    WHERE data_exposure_risk != 'none';

-- CTEM priority index (internet-facing + high severity)
CREATE INDEX IF NOT EXISTS idx_findings_ctem_priority ON findings(tenant_id, severity)
    WHERE is_internet_accessible = true
    AND status IN ('new', 'confirmed', 'in_progress')
    AND severity IN ('critical', 'high');

-- SARIF indexes
CREATE INDEX IF NOT EXISTS idx_findings_baseline_state ON findings(baseline_state) WHERE baseline_state IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_correlation_id ON findings(correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(impact, likelihood) WHERE impact IS NOT NULL;

-- Type-specific indexes
CREATE INDEX IF NOT EXISTS idx_findings_secret_type ON findings(secret_type) WHERE finding_type = 'secret';
CREATE INDEX IF NOT EXISTS idx_findings_secret_service ON findings(secret_service) WHERE finding_type = 'secret';
CREATE INDEX IF NOT EXISTS idx_findings_compliance_framework ON findings(compliance_framework) WHERE finding_type = 'compliance';
CREATE INDEX IF NOT EXISTS idx_findings_compliance_framework_result ON findings(compliance_framework, compliance_result) WHERE finding_type = 'compliance';
CREATE INDEX IF NOT EXISTS idx_findings_web3_chain ON findings(web3_chain) WHERE finding_type = 'web3';
CREATE INDEX IF NOT EXISTS idx_findings_web3_contract ON findings(web3_contract_address) WHERE finding_type = 'web3';
CREATE INDEX IF NOT EXISTS idx_findings_misconfig_policy ON findings(misconfig_policy_id) WHERE finding_type = 'misconfiguration';

-- Finding comments indexes
CREATE INDEX IF NOT EXISTS idx_finding_comments_finding_id ON finding_comments(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_comments_author_id ON finding_comments(author_id);
CREATE INDEX IF NOT EXISTS idx_finding_comments_created_at ON finding_comments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_comments_status_change ON finding_comments(finding_id) WHERE is_status_change = TRUE;

-- Finding activities indexes
CREATE INDEX IF NOT EXISTS idx_finding_activities_tenant ON finding_activities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_finding_activities_finding ON finding_activities(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_activities_actor ON finding_activities(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_finding_activities_type ON finding_activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_finding_activities_created ON finding_activities(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_activities_tenant_finding ON finding_activities(tenant_id, finding_id);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_findings_updated_at ON findings;
CREATE TRIGGER trigger_findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_finding_comments_updated_at ON finding_comments;
CREATE TRIGGER trigger_finding_comments_updated_at
    BEFORE UPDATE ON finding_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to sync comments_count on findings
CREATE OR REPLACE FUNCTION update_finding_comments_count() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE findings
        SET comments_count = comments_count + 1,
            updated_at = NOW()
        WHERE id = NEW.finding_id;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE findings
        SET comments_count = GREATEST(comments_count - 1, 0),
            updated_at = NOW()
        WHERE id = OLD.finding_id;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_finding_comments_count() IS 'Keeps findings.comments_count in sync when comments are added/deleted';

DROP TRIGGER IF EXISTS trigger_finding_comments_count ON finding_comments;
CREATE TRIGGER trigger_finding_comments_count
    AFTER INSERT OR DELETE ON finding_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_finding_comments_count();
