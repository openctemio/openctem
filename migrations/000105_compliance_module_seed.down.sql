-- =============================================================================
-- Migration 105 (down): Remove compliance module seed row.
--
-- Best-effort delete. If a tenant has a `tenant_modules` override referencing
-- this module the FK should ON DELETE CASCADE (or SET NULL) per the parent
-- table definition; we do not duplicate that policy here.
-- =============================================================================

DELETE FROM modules WHERE id = 'compliance';
