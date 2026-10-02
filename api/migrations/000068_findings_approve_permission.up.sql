-- Add dedicated findings:approve permission for approval workflow separation of duties.
-- Only Owner and Admin roles can approve/reject finding status changes.

INSERT INTO permissions (id, module_id, name, description) VALUES
  ('findings:approve', 'findings', 'Approve Findings', 'Approve or reject finding status change requests')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description;

-- Assign to Owner role
INSERT INTO role_permissions (role_id, permission_id) VALUES
  ('00000000-0000-0000-0000-000000000001', 'findings:approve')
ON CONFLICT DO NOTHING;

-- Assign to Admin role
INSERT INTO role_permissions (role_id, permission_id) VALUES
  ('00000000-0000-0000-0000-000000000002', 'findings:approve')
ON CONFLICT DO NOTHING;
