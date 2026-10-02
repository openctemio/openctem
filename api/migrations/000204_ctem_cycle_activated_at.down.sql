-- Revert Migration 000204: drop the CTEM cycle activation timestamp.
ALTER TABLE ctem_cycles DROP COLUMN IF EXISTS activated_at;
