-- service_accounts:manage: create and delete service accounts and mint and
-- delete their API keys. These routes used team:members:write, so any
-- delegated member manager could create an integration identity or its
-- credential. Owners and admins get the new permission; custom roles do not
-- (an owner may add it to a role).
INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
VALUES
    ('service_accounts:manage', 'team', 'Manage Service Accounts',
     'Create and delete service accounts and mint and delete their API keys', true, now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (id, role_id, permission_id, created_at)
SELECT uuid_generate_v7(), r.id, 'service_accounts:manage', now()
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
  AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = 'service_accounts:manage');
