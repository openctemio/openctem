-- Revert Migration 000231 (scan zones). Exact inverse of the up migration.
DELETE FROM role_permissions
WHERE permission_id IN ('sensors:zones:read', 'sensors:zones:write', 'sensors:zones:delete');
DELETE FROM group_permissions
WHERE permission_id IN ('sensors:zones:read', 'sensors:zones:write', 'sensors:zones:delete');
DELETE FROM permission_set_items
WHERE permission_id IN ('sensors:zones:read', 'sensors:zones:write', 'sensors:zones:delete');
DELETE FROM permissions
WHERE id IN ('sensors:zones:read', 'sensors:zones:write', 'sensors:zones:delete');

DROP INDEX IF EXISTS idx_commands_scan_zone_active;
ALTER TABLE commands DROP COLUMN IF EXISTS scan_zone_id;

DROP TABLE IF EXISTS scan_zone_sensors;
DROP TABLE IF EXISTS scan_zones;

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS uq_sensors_tenant_id_id;
