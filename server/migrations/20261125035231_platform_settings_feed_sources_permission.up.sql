-- platform_settings_feed_sources_permission: the vulnerability feed address
-- (console System > Threat intelligence > Feed address: release URL and
-- mirrors, and the test fetch) is changed with platform.settings.feed_sources,
-- a platform owner permission (the code gives the owner the whole catalog;
-- this row mirrors it).
INSERT INTO platform_role_permissions (role_id, permission)
SELECT r.id, 'platform.settings.feed_sources'
FROM platform_roles r
WHERE r.key = 'platform_owner'
ON CONFLICT DO NOTHING;
