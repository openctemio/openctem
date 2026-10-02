-- =============================================================================
-- Migration 000058: System Tenant + Quick Scan Template
-- OpenCTEM OSS Edition
-- =============================================================================
-- Creates the platform system tenant used for system-level resources:
--   - System scan profiles (available to all tenants)
--   - Preset pipeline templates
--   - Quick Scan template for single-scanner scans
-- Source: old migration 000088
-- =============================================================================

-- =============================================================================
-- 1. System Tenant
-- =============================================================================
INSERT INTO tenants (id, name, slug, description, settings)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'System',
    'system',
    'Platform system tenant for internal operations',
    '{"is_system": true}'::jsonb
)
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- 2. Quick Scan Template
-- =============================================================================
-- Used by Quick Scan API for single-scanner scans.
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    settings, is_active, is_system_template, tags
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000000',
    'Quick Scan Template',
    'System template for quick single-scanner scans',
    1,
    '{"max_parallel_steps": 1, "timeout_seconds": 7200, "fail_fast": true}'::jsonb,
    true,
    true,
    ARRAY['system', 'quick-scan']
)
ON CONFLICT (id) DO NOTHING;

-- Quick Scan Step
INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description,
    step_order, capabilities, config, timeout_seconds
) VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'quick_scan',
    'Quick Scan Step',
    'Executes the requested scanner on target assets',
    1,
    ARRAY['scan'],
    '{}'::jsonb,
    7200
)
ON CONFLICT (id) DO NOTHING;
