-- Restores the member grants the up migration removed.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, p.id
FROM permissions p
WHERE p.id IN ('scans:templates:write', 'scans:sources:write')
ON CONFLICT DO NOTHING;
