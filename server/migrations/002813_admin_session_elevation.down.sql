ALTER TABLE admin_sessions
    DROP COLUMN IF EXISTS elevation_reason,
    DROP COLUMN IF EXISTS elevated_until,
    DROP COLUMN IF EXISTS elevated_role;
