-- =============================================================================
-- Migration 000053 DOWN: Drop Scan, Dependency & Command Performance Indexes
-- =============================================================================

-- Module hierarchy
DROP INDEX IF EXISTS idx_modules_release_status_active;
DROP INDEX IF EXISTS idx_modules_parent_active_order;
DROP INDEX IF EXISTS idx_modules_parent_module_id;

-- Command recovery
DROP INDEX IF EXISTS idx_commands_dispatch_retries;
DROP INDEX IF EXISTS idx_commands_tenant_stuck;

-- Dependency tree
DROP INDEX IF EXISTS idx_asset_components_direct_deps;
DROP INDEX IF EXISTS idx_asset_components_risk_query;
DROP INDEX IF EXISTS idx_asset_components_depth;

-- Scan performance
DROP INDEX IF EXISTS idx_scans_custom_targets;
DROP INDEX IF EXISTS idx_scans_active_scheduled;
DROP INDEX IF EXISTS idx_scans_tenant_status_schedule;
DROP INDEX IF EXISTS idx_scans_tenant_type;
DROP INDEX IF EXISTS idx_scans_tenant_schedule;
DROP INDEX IF EXISTS idx_scans_tenant_created;
