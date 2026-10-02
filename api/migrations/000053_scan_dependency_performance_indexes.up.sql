-- =============================================================================
-- Migration 000053: Scan, Dependency & Command Performance Indexes
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds composite indexes that speed up:
-- - Scan listing, filtering, and scheduler queries
-- - Dependency tree traversal and risk analysis
-- - Command recovery and dispatch retry queries
-- - Module hierarchy navigation
-- All use IF NOT EXISTS for idempotency.
-- =============================================================================

-- =============================================================================
-- 1. Scan Performance Indexes
-- =============================================================================

-- Scan listing with default sort (newest first)
CREATE INDEX IF NOT EXISTS idx_scans_tenant_created
    ON scans(tenant_id, created_at DESC);

-- Schedule type filter
CREATE INDEX IF NOT EXISTS idx_scans_tenant_schedule
    ON scans(tenant_id, schedule_type);

-- Scan type filter
CREATE INDEX IF NOT EXISTS idx_scans_tenant_type
    ON scans(tenant_id, scan_type);

-- Composite: status + schedule for dashboard queries
CREATE INDEX IF NOT EXISTS idx_scans_tenant_status_schedule
    ON scans(tenant_id, status, schedule_type);

-- Scheduler: find active scans that need to run
CREATE INDEX IF NOT EXISTS idx_scans_active_scheduled
    ON scans(next_run_at)
    WHERE status = 'active'
      AND schedule_type != 'manual'
      AND next_run_at IS NOT NULL;

-- Custom target scan lookup
CREATE INDEX IF NOT EXISTS idx_scans_custom_targets
    ON scans USING GIN(targets)
    WHERE array_length(targets, 1) > 0;

-- =============================================================================
-- 2. Dependency Tree Indexes (asset_components)
-- =============================================================================

-- Depth-based queries (e.g., show only direct dependencies)
CREATE INDEX IF NOT EXISTS idx_asset_components_depth
    ON asset_components(asset_id, depth);

-- Risk analysis: type + depth composite
CREATE INDEX IF NOT EXISTS idx_asset_components_risk_query
    ON asset_components(asset_id, dependency_type, depth);

-- Direct dependencies only (depth=0 in new project, depth=1 in old)
CREATE INDEX IF NOT EXISTS idx_asset_components_direct_deps
    ON asset_components(asset_id, component_id)
    WHERE depth = 0;

-- =============================================================================
-- 3. Command Recovery & Dispatch Indexes
-- =============================================================================

-- Find stuck tenant commands for recovery job
CREATE INDEX IF NOT EXISTS idx_commands_tenant_stuck
    ON commands(agent_id, status, created_at)
    WHERE is_platform_job = FALSE
      AND agent_id IS NOT NULL
      AND status = 'pending';

-- Find commands with failed dispatch attempts
CREATE INDEX IF NOT EXISTS idx_commands_dispatch_retries
    ON commands(dispatch_attempts, status)
    WHERE dispatch_attempts > 0
      AND status = 'pending';

-- =============================================================================
-- 4. Module Hierarchy Indexes
-- =============================================================================

-- Parent module lookup (for sidebar tree)
CREATE INDEX IF NOT EXISTS idx_modules_parent_module_id
    ON modules(parent_module_id)
    WHERE parent_module_id IS NOT NULL;

-- Parent + active + display order (sidebar rendering)
CREATE INDEX IF NOT EXISTS idx_modules_parent_active_order
    ON modules(parent_module_id, is_active, display_order)
    WHERE parent_module_id IS NOT NULL;

-- Active modules by release status (feature flags)
CREATE INDEX IF NOT EXISTS idx_modules_release_status_active
    ON modules(release_status, is_active)
    WHERE is_active = true;
