-- reports:manage: pause, resume and delete report schedules other members
-- created, and see their recipients. Without it a member with reports:write
-- changes only the schedules they created. Owners and admins get it.
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('reports:manage', 'reports', 'Manage Report Schedules',
     'Pause, resume and delete report schedules created by other members and see their recipients', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'reports:manage'
  FROM roles r
 WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;
