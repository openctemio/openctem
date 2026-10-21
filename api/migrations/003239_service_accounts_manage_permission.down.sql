UPDATE roles
   SET template_permissions = array_remove(template_permissions, 'service_accounts:manage')
 WHERE template_permissions @> ARRAY['service_accounts:manage'];

UPDATE api_keys SET scopes = array_remove(scopes, 'service_accounts:manage') WHERE 'service_accounts:manage' = ANY(scopes);
DELETE FROM role_permissions WHERE permission_id = 'service_accounts:manage';
DELETE FROM permissions WHERE id = 'service_accounts:manage';
