-- AUTHZ-05: the finding action routes (assign, unassign, status, triage, bulk)
-- were gated on the coarse findings:write. They are now gated on the precise
-- findings:assign / findings:status / findings:triage / findings:bulk_update.
--
-- To keep behavior IDENTICAL, grant those granular permissions to every role
-- that currently holds findings:write, so any role that could perform these
-- actions before still can. Purely additive (ON CONFLICT DO NOTHING) — no role
-- loses any permission. Precision + honest role matrix, zero behavior change;
-- tightening who gets assign/bulk is a separate product decision.
INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, g.perm
FROM role_permissions rp
CROSS JOIN (VALUES
    ('findings:assign'),
    ('findings:status'),
    ('findings:triage'),
    ('findings:bulk_update')
) AS g(perm)
WHERE rp.permission_id = 'findings:write'
ON CONFLICT (role_id, permission_id) DO NOTHING;
