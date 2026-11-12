-- platform_mfa_floor_permission (up)
-- The platform two-factor floor gets its own permission, held by the owner
-- role only (the code gives the owner the whole catalog; these rows mirror it).
INSERT INTO platform_role_permissions (role_id, permission)
SELECT r.id, 'platform.settings.mfa'
FROM platform_roles r
WHERE r.key = 'platform_owner'
ON CONFLICT DO NOTHING;
