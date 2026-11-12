-- Restores the Member grant removed by the up migration. Queued recomputes
-- are not undone (they only recompute).

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, 'ctem:compensating_controls:write'
WHERE EXISTS (SELECT 1 FROM roles WHERE id = '00000000-0000-0000-0000-000000000003')
ON CONFLICT (role_id, permission_id) DO NOTHING;
