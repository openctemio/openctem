DROP TABLE IF EXISTS scan_approval_requests;

DELETE FROM role_permissions WHERE permission_id = 'scans:approve';
DELETE FROM permissions WHERE id = 'scans:approve';
