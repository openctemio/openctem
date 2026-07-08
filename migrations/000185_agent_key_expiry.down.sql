DROP INDEX IF EXISTS idx_agents_key_expires_at;
ALTER TABLE agents DROP COLUMN IF EXISTS key_expires_at;
