DELETE FROM role_permissions WHERE permission_id IN ('content:read', 'content:install');
DELETE FROM permissions WHERE id IN ('content:read', 'content:install');

DROP TABLE IF EXISTS content_catalog_settings;
DROP TABLE IF EXISTS content_install_requests;
DROP TABLE IF EXISTS content_installs;
DROP TABLE IF EXISTS content_revocations;
DROP TABLE IF EXISTS content_packages;
DROP TABLE IF EXISTS content_catalog_trust;
