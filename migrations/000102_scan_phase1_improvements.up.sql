-- =============================================================================
-- Migration 102: Scan Phase 1 Improvements
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds missing columns and FK constraints to scan-related tables:
--   1. scans.agent_preference - agent selection mode (auto/tenant/platform)
--   2. scans.profile_id - link scan to scan profile (tool configs, quality gates)
--   3. scans.timeout_seconds - max execution time before forced timeout
--   4. scans.last_run_id FK constraint to pipeline_runs (referential integrity)
--   5. pipeline_runs.scan_id FK constraint to scans (referential integrity)

BEGIN;

-- =============================================================================
-- 1. agent_preference column
-- =============================================================================
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS agent_preference VARCHAR(20) NOT NULL DEFAULT 'auto';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_agent_preference'
    ) THEN
        ALTER TABLE scans ADD CONSTRAINT chk_scans_agent_preference
            CHECK (agent_preference IN ('auto', 'tenant', 'platform'));
    END IF;
END $$;

COMMENT ON COLUMN scans.agent_preference IS
    'Agent selection mode: auto = best match, tenant = tenant-owned only, platform = shared platform agents';

-- =============================================================================
-- 2. profile_id column - link to scan_profiles
-- =============================================================================
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS profile_id UUID
    REFERENCES scan_profiles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_scans_profile ON scans(profile_id) WHERE profile_id IS NOT NULL;

COMMENT ON COLUMN scans.profile_id IS
    'Optional reference to a scan profile that provides tool configs, intensity, and quality gates';

-- =============================================================================
-- 3. timeout_seconds column - max execution time
-- =============================================================================
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS timeout_seconds INTEGER NOT NULL DEFAULT 3600;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_timeout_seconds'
    ) THEN
        ALTER TABLE scans ADD CONSTRAINT chk_scans_timeout_seconds
            CHECK (timeout_seconds > 0 AND timeout_seconds <= 86400);
    END IF;
END $$;

COMMENT ON COLUMN scans.timeout_seconds IS
    'Maximum execution time in seconds before scan is forcefully marked as timeout (max 24h)';

-- =============================================================================
-- 4. scans.last_run_id FK to pipeline_runs (referential integrity)
-- =============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_scans_last_run'
    ) THEN
        -- Clear orphaned references first to avoid FK violation
        UPDATE scans
        SET last_run_id = NULL
        WHERE last_run_id IS NOT NULL
          AND last_run_id NOT IN (SELECT id FROM pipeline_runs);

        ALTER TABLE scans ADD CONSTRAINT fk_scans_last_run
            FOREIGN KEY (last_run_id) REFERENCES pipeline_runs(id) ON DELETE SET NULL;
    END IF;
END $$;

-- =============================================================================
-- 5. pipeline_runs.scan_id FK to scans (referential integrity)
-- =============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_pipeline_runs_scan'
    ) THEN
        -- Clear orphaned references first to avoid FK violation
        UPDATE pipeline_runs
        SET scan_id = NULL
        WHERE scan_id IS NOT NULL
          AND scan_id NOT IN (SELECT id FROM scans);

        ALTER TABLE pipeline_runs ADD CONSTRAINT fk_pipeline_runs_scan
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_scan ON pipeline_runs(scan_id) WHERE scan_id IS NOT NULL;

COMMIT;
