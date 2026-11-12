-- scope_name_exceptions (down)
DELETE FROM platform_role_permissions WHERE permission = 'platform.settings.scope_guardrails';
DROP TABLE IF EXISTS scope_name_exceptions;
