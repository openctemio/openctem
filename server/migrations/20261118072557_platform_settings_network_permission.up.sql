-- platform_settings_network_permission: the private network destinations
-- setting (console System > Private network destinations) is changed with
-- platform.settings.network, a platform owner permission (the code gives the
-- owner the whole catalog; this row mirrors it).
INSERT INTO platform_role_permissions (role_id, permission)
SELECT r.id, 'platform.settings.network'
FROM platform_roles r
WHERE r.key = 'platform_owner'
ON CONFLICT DO NOTHING;
