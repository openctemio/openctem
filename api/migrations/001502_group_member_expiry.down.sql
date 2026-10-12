DROP INDEX IF EXISTS idx_group_members_expires_at;
ALTER TABLE group_members
    DROP COLUMN IF EXISTS expiry_reason,
    DROP COLUMN IF EXISTS expires_at;
