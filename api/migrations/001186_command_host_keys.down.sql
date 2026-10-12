DROP INDEX IF EXISTS idx_commands_active_host_keys;
ALTER TABLE commands DROP COLUMN IF EXISTS host_keys;
