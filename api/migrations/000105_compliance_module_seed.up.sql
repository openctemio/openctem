-- =============================================================================
-- Migration 105: Compliance Module Seed
--
-- The compliance feature was implemented end-to-end (domain, service, handler,
-- routes, frontend page, sidebar entry, permission constant), but the row in
-- the `modules` registry was never seeded. This left the sidebar entry pointing
-- at module='compliance' which did not exist, so:
--   - Tenant admins could not see/toggle the Compliance feature in
--     Settings > Organization > Modules
--   - Module-permission mapping in pkg/domain/module/module.go referenced
--     a phantom "compliance" entry
--   - Frontend `module: 'compliance'` filter on the sidebar item was a no-op
--
-- This migration adds the missing row using the same INSERT shape as the seed
-- in 000004_modules.up.sql. ON CONFLICT DO UPDATE so re-running the migration
-- (and any future re-runs of the original seed) stays idempotent.
-- =============================================================================

INSERT INTO modules (
    id,
    slug,
    name,
    description,
    icon,
    category,
    display_order,
    is_active,
    release_status
) VALUES (
    'compliance',
    'compliance',
    'Compliance',
    'Compliance frameworks, controls and audit-readiness mappings',
    'ClipboardCheck',
    'compliance',
    90,
    true,
    'released'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    category = EXCLUDED.category,
    display_order = EXCLUDED.display_order,
    is_active = EXCLUDED.is_active,
    release_status = EXCLUDED.release_status,
    updated_at = NOW();
