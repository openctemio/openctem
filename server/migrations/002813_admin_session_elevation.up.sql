-- Time-boxed role elevation of a console session: administrators act as
-- read-only until they elevate, with a reason and a fresh confirmation, for
-- 15 to 60 minutes (the role and duration are checked in code; the role is
-- never above the administrator's own). admin_sessions is small: nullable
-- columns without defaults are catalog-only changes.
ALTER TABLE admin_sessions
    ADD COLUMN IF NOT EXISTS elevated_role text,
    ADD COLUMN IF NOT EXISTS elevated_until timestamptz,
    ADD COLUMN IF NOT EXISTS elevation_reason text;
