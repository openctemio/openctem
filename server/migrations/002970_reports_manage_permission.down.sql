UPDATE roles
   SET template_permissions = array_remove(template_permissions, 'reports:manage')
 WHERE template_permissions @> ARRAY['reports:manage'];

UPDATE api_keys
   SET scopes = array_remove(scopes, 'reports:manage')
 WHERE scopes @> ARRAY['reports:manage'];

DELETE FROM role_permissions WHERE permission_id = 'reports:manage';
DELETE FROM permissions WHERE id = 'reports:manage';
