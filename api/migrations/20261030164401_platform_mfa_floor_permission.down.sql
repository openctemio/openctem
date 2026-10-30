-- platform_mfa_floor_permission (down)
DELETE FROM platform_role_permissions WHERE permission = 'platform.settings.mfa';
