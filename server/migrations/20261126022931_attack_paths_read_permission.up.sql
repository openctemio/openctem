-- attack_surface:paths:read: reading the computed attack routes (attack-path
-- scores and detail, exposure chains, threat models). Until now these needed
-- only assets:read.
--
-- No one who reads them today loses them: the owner, administrator and member
-- system roles get the permission, and so does every custom role that holds
-- assets:read. The viewer system role does not (it keeps the inventory and its
-- relationships). API keys and MCP grants carry explicit scopes and are not
-- widened: a key must name the new scope to read attack routes.

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
VALUES
    ('attack_surface:paths:read', 'attack_surface', 'View Attack Paths',
     'View computed attack routes: attack-path scores and detail, exposure chains and threat models', true, now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (id, role_id, permission_id, created_at)
SELECT uuid_generate_v7(), r.id, 'attack_surface:paths:read', now()
FROM roles r
WHERE (
        r.id IN ('00000000-0000-0000-0000-000000000001',
                 '00000000-0000-0000-0000-000000000002',
                 '00000000-0000-0000-0000-000000000003')
        OR (r.tenant_id IS NOT NULL
            AND EXISTS (SELECT 1 FROM role_permissions h
                        WHERE h.role_id = r.id AND h.permission_id = 'assets:read'))
      )
  AND NOT EXISTS (SELECT 1 FROM role_permissions rp
                  WHERE rp.role_id = r.id AND rp.permission_id = 'attack_surface:paths:read');
