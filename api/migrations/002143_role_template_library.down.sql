-- Restores the built-in Researcher role and moves the per-organization copies
-- the up migration made back onto it.

INSERT INTO roles (id, tenant_id, slug, name, description, is_system, hierarchy_level, has_full_data_access)
VALUES ('00000000-0000-0000-0000-000000000005', NULL, 'researcher', 'Researcher',
        'Tests programs the organization follows: programs, scans and findings of the programs they belong to; cannot change the organization''s own scope or approve anything',
        true, 30, false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000005'::uuid, p.id
FROM permissions p
WHERE p.id IN ('dashboard:read', 'assets:read',
               'findings:read', 'findings:write', 'findings:comment', 'findings:status', 'findings:triage', 'findings:export',
               'scans:read', 'scans:write', 'scans:execute',
               'scans:profiles:read', 'scans:templates:read', 'scans:workflows:read',
               'sensors:read',
               'attack_surface:programs:read', 'attack_surface:programs:write')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Copies the up migration made: template "researcher", slug researcher or
-- researcher-role, never bound to a team.
INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
SELECT ur.user_id, ur.tenant_id, '00000000-0000-0000-0000-000000000005', ur.assigned_at, ur.assigned_by
FROM user_roles ur JOIN roles c ON c.id = ur.role_id
WHERE NOT c.is_system AND c.template_id = 'researcher' AND c.slug IN ('researcher', 'researcher-role')
  AND NOT EXISTS (SELECT 1 FROM group_role_bindings b WHERE b.role_id = c.id)
ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING;

UPDATE tenant_invitations i
SET role_ids = array_replace(i.role_ids, c.id, '00000000-0000-0000-0000-000000000005'::uuid)
FROM roles c
WHERE c.id = ANY (i.role_ids) AND c.tenant_id = i.tenant_id
  AND NOT c.is_system AND c.template_id = 'researcher' AND c.slug IN ('researcher', 'researcher-role')
  AND NOT EXISTS (SELECT 1 FROM group_role_bindings b WHERE b.role_id = c.id);

DELETE FROM roles c
WHERE NOT c.is_system AND c.template_id = 'researcher' AND c.slug IN ('researcher', 'researcher-role')
  AND NOT EXISTS (SELECT 1 FROM group_role_bindings b WHERE b.role_id = c.id);

-- expand-contract-ok: down migration restores the previous check
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved;
ALTER TABLE roles ADD CONSTRAINT roles_custom_slug_not_reserved
    CHECK (is_system OR lower(btrim(slug)) !~ '^(owner|admin|member|viewer|researcher)$') NOT VALID;

ALTER TABLE roles DROP CONSTRAINT IF EXISTS chk_roles_template_origin;
-- expand-contract-ok: down migration of a column added in the same migration
ALTER TABLE roles
    DROP COLUMN IF EXISTS template_permissions,
    DROP COLUMN IF EXISTS template_version,
    DROP COLUMN IF EXISTS template_id;
