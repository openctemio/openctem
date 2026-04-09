-- =============================================================================
-- Migration 109: Member suspension lifecycle
--
-- Adds a status field to tenant_members so admins can SUSPEND a user's
-- access without permanently deleting the membership row. This preserves:
--   - Audit trail (who was a member, when, with what roles)
--   - Asset ownership attribution (findings, relationships, owners)
--   - Compliance evidence ("was user X active on date Y?")
--
-- Use cases:
--   - Employee leaves the company → suspend first, remove later
--   - Employee on leave → suspend temporarily, reactivate on return
--   - Security incident → suspend immediately to revoke access
--   - Contractor engagement ends → suspend to preserve attribution
--
-- The three-state lifecycle:
--   active → suspended → (reactivate back to active | remove permanently)
--
-- JWT validation should check membership status at exchange time:
-- a suspended user gets a 403 when trying to exchange a refresh token
-- for a tenant-scoped access token.
-- =============================================================================

-- Add the status column with default 'active' so existing rows are
-- unaffected. The CHECK constraint enforces only valid transitions.
ALTER TABLE tenant_members
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS suspended_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Constraint on status values
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_tenant_members_status'
    ) THEN
        ALTER TABLE tenant_members
            ADD CONSTRAINT chk_tenant_members_status
            CHECK (status IN ('active', 'suspended'));
    END IF;
END $$;

-- Index for filtering active vs suspended members. Partial index on
-- 'suspended' to speed up the "show me all suspended members" admin
-- query without bloating the index with the (much larger) active set.
CREATE INDEX IF NOT EXISTS idx_tenant_members_suspended
    ON tenant_members (tenant_id)
    WHERE status = 'suspended';

COMMENT ON COLUMN tenant_members.status IS 'Membership lifecycle: active (full access) or suspended (access revoked, history preserved)';
COMMENT ON COLUMN tenant_members.suspended_at IS 'When the membership was suspended. NULL when active.';
COMMENT ON COLUMN tenant_members.suspended_by IS 'Who suspended the membership. NULL when active.';
