-- =============================================================================
-- Migration 032: Scans (Scan Configurations)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Scan Configurations: Binding Asset Group + Scanner/Workflow + Schedule
-- This table represents the core "Scan Config" concept that binds:
-- 1. Target (Asset Group)
-- 2. What to run (Workflow pipeline OR Single scanner)
-- 3. When to run (Schedule)
-- 4. Where to run (Agent routing via tags)

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,

    -- Target: Asset Group(s) to scan
    asset_group_id UUID REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_group_ids UUID[] DEFAULT '{}',
    targets TEXT[] DEFAULT '{}',

    -- Scan Type: Workflow (multi-step pipeline) OR Single (one scanner)
    scan_type VARCHAR(20) NOT NULL,

    -- If scan_type = 'workflow': reference to pipeline template
    pipeline_id UUID REFERENCES pipeline_templates(id) ON DELETE SET NULL,

    -- If scan_type = 'single': scanner configuration
    scanner_name VARCHAR(100),           -- Tool name from tool registry (e.g., 'nuclei', 'semgrep')
    scanner_config JSONB DEFAULT '{}',   -- Scanner-specific configuration
    targets_per_job INTEGER DEFAULT 1,   -- Number of targets to process per job

    -- Schedule Configuration
    schedule_type VARCHAR(20) NOT NULL DEFAULT 'manual',
    schedule_cron VARCHAR(100),          -- Cron expression (only if schedule_type = 'crontab')
    schedule_day INTEGER,                -- Day of week (0-6) or day of month (1-31)
    schedule_time TIME,                  -- Time of day to run
    schedule_timezone VARCHAR(50) DEFAULT 'UTC',
    next_run_at TIMESTAMPTZ,             -- Computed next run time

    -- Agent Routing
    tags TEXT[] DEFAULT '{}',            -- Route jobs to agents with matching tags
    run_on_tenant_runner BOOLEAN DEFAULT false,  -- Restrict to tenant's own agents only

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    -- Execution Statistics
    last_run_id UUID,                    -- Reference to last pipeline_run
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    total_runs INTEGER DEFAULT 0,
    successful_runs INTEGER DEFAULT 0,
    failed_runs INTEGER DEFAULT 0,

    -- Audit Fields
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT scans_tenant_name_unique UNIQUE(tenant_id, name),
    CONSTRAINT chk_scans_scan_type CHECK (scan_type IN ('workflow', 'single')),
    CONSTRAINT chk_scans_schedule_type CHECK (schedule_type IN ('manual', 'daily', 'weekly', 'monthly', 'crontab')),
    CONSTRAINT chk_scans_status CHECK (status IN ('active', 'paused', 'disabled')),

    -- Ensure workflow type has pipeline_id
    CONSTRAINT scans_chk_workflow_has_pipeline
        CHECK (scan_type != 'workflow' OR pipeline_id IS NOT NULL),

    -- Ensure single type has scanner_name
    CONSTRAINT scans_chk_single_has_scanner
        CHECK (scan_type != 'single' OR scanner_name IS NOT NULL),

    -- Ensure at least one target source (asset_group_id, asset_group_ids, or direct targets)
    CONSTRAINT chk_scan_has_targets
        CHECK (
            asset_group_id IS NOT NULL
            OR (asset_group_ids IS NOT NULL AND array_length(asset_group_ids, 1) > 0)
            OR (targets IS NOT NULL AND array_length(targets, 1) > 0)
        )
);

COMMENT ON TABLE scans IS 'Scan configurations that bind asset groups with scanners/workflows and schedules';
COMMENT ON COLUMN scans.asset_group_ids IS 'Multiple asset group IDs - extends single asset_group_id for multi-group scans';
COMMENT ON COLUMN scans.scan_type IS 'workflow = multi-step pipeline, single = one scanner execution';
COMMENT ON COLUMN scans.targets_per_job IS 'Number of targets (assets) to include in each job batch';
COMMENT ON COLUMN scans.tags IS 'Tags for routing jobs to specific agents';
COMMENT ON COLUMN scans.run_on_tenant_runner IS 'When true, jobs only run on agents owned by this tenant';
COMMENT ON COLUMN scans.targets IS 'Direct targets to scan (IPs, domains, URLs) - alternative to asset groups';
COMMENT ON COLUMN scans.next_run_at IS 'Pre-computed next scheduled run time for efficient scheduling queries';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_asset_group ON scans(asset_group_id) WHERE asset_group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scans_asset_group_ids ON scans USING GIN(asset_group_ids) WHERE asset_group_ids IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scans_pipeline ON scans(pipeline_id) WHERE pipeline_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_schedule_type ON scans(schedule_type) WHERE schedule_type != 'manual';
CREATE INDEX IF NOT EXISTS idx_scans_next_run ON scans(next_run_at) WHERE status = 'active' AND schedule_type != 'manual';
CREATE INDEX IF NOT EXISTS idx_scans_tags ON scans USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_scans_scanner ON scans(scanner_name) WHERE scan_type = 'single';
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_status ON scans(tenant_id, status);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_scans_updated_at ON scans;
CREATE TRIGGER trigger_scans_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
