-- Reverses 001110_scan_freeze_windows.up.sql.

DELETE FROM role_permissions WHERE permission_id = 'scans:freeze:override';
DELETE FROM permissions WHERE id = 'scans:freeze:override';

ALTER TABLE commands DROP COLUMN IF EXISTS freeze_override;
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS freeze_override;

DROP TABLE IF EXISTS scan_freeze_windows;
