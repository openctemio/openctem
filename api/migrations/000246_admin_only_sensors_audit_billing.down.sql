-- Restores the grants the up migration removed: member had all three, viewer
-- had audit:read and settings:billing:read (never sensors:write).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, r.permission_id
FROM (VALUES
    ('00000000-0000-0000-0000-000000000003'::uuid, 'sensors:write'),
    ('00000000-0000-0000-0000-000000000003'::uuid, 'audit:read'),
    ('00000000-0000-0000-0000-000000000003'::uuid, 'settings:billing:read'),
    ('00000000-0000-0000-0000-000000000004'::uuid, 'audit:read'),
    ('00000000-0000-0000-0000-000000000004'::uuid, 'settings:billing:read')
) AS r(role_id, permission_id)
JOIN permissions p ON p.id = r.permission_id
ON CONFLICT DO NOTHING;
