DROP INDEX IF EXISTS idx_scans_tenant_scan_zone;
ALTER TABLE scans DROP COLUMN IF EXISTS scan_zone_id;
