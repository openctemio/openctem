-- =============================================================================
-- Migration 109 (down): remove member suspension columns.
-- =============================================================================

DROP INDEX IF EXISTS idx_tenant_members_suspended;
ALTER TABLE tenant_members DROP CONSTRAINT IF EXISTS chk_tenant_members_status;
ALTER TABLE tenant_members
    DROP COLUMN IF EXISTS suspended_by,
    DROP COLUMN IF EXISTS suspended_at,
    DROP COLUMN IF EXISTS status;
