-- =============================================================================
-- Migration 000058 DOWN: Remove System Tenant + Quick Scan Template
-- =============================================================================

DELETE FROM pipeline_steps WHERE id = '00000000-0000-0000-0000-000000000002';
DELETE FROM pipeline_templates WHERE id = '00000000-0000-0000-0000-000000000001';
DELETE FROM tenants WHERE id = '00000000-0000-0000-0000-000000000000';
