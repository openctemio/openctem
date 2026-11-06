ALTER TABLE users
    DROP COLUMN IF EXISTS blocked_reason,
    DROP COLUMN IF EXISTS blocked_by,
    DROP COLUMN IF EXISTS blocked_at;

DROP INDEX IF EXISTS idx_tenants_not_active;

ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS chk_tenants_status,
    DROP COLUMN IF EXISTS suspended_reason,
    DROP COLUMN IF EXISTS suspended_by,
    DROP COLUMN IF EXISTS suspended_at,
    DROP COLUMN IF EXISTS status;
