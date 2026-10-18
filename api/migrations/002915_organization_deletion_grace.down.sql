-- An organization waiting for deletion goes back to active: without the
-- grace columns nothing would ever delete it, and an older API knows only
-- active and suspended.
UPDATE tenants SET status = 'active' WHERE status = 'pending_deletion';

DROP INDEX IF EXISTS idx_tenants_deletion_due;

ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS chk_tenants_deletion_due,
    DROP COLUMN IF EXISTS deletion_due_at,
    DROP COLUMN IF EXISTS deletion_requested_by,
    DROP COLUMN IF EXISTS deletion_requested_at,
    DROP CONSTRAINT IF EXISTS chk_tenants_status,
    ADD CONSTRAINT chk_tenants_status CHECK (status IN ('active', 'suspended'));
