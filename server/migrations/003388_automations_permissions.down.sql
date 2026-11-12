-- automations:read and automations:write go back to findings:workflows:*;
-- automations:publish is dropped (its holders keep findings:workflows:write,
-- which switched automations on before).
INSERT INTO permissions (id, module_id, name, description, is_active, created_at) VALUES
    ('findings:workflows:read', 'remediation', 'View Workflows', 'View automation workflows', true, now()),
    ('findings:workflows:write', 'remediation', 'Manage Workflows', 'Create and update workflows', true, now())
ON CONFLICT (id) DO NOTHING;

UPDATE role_permissions SET permission_id = 'findings:workflows:read' WHERE permission_id = 'automations:read';
UPDATE role_permissions SET permission_id = 'findings:workflows:write' WHERE permission_id = 'automations:write';
DELETE FROM role_permissions WHERE permission_id = 'automations:publish';
UPDATE api_keys SET scopes = array_remove(array_replace(array_replace(scopes, 'automations:read', 'findings:workflows:read'),
                                                        'automations:write', 'findings:workflows:write'), 'automations:publish')
 WHERE scopes && ARRAY['automations:read', 'automations:write', 'automations:publish'];
UPDATE roles SET template_permissions = array_replace(array_replace(template_permissions, 'automations:read', 'findings:workflows:read'),
                                                      'automations:write', 'findings:workflows:write')
 WHERE template_permissions && ARRAY['automations:read', 'automations:write'];
UPDATE roles SET template_version = 2
 WHERE template_id IN ('security-analyst', 'vulnerability-manager') AND template_version = 3;
DELETE FROM permissions WHERE id IN ('automations:read', 'automations:write', 'automations:publish');
