-- Role templates (RFC-095): a custom role remembers the template version it
-- was created from, and the built-in Researcher role becomes the
-- "researcher" template.
--
-- Built-in roles are now owner, admin, member and viewer. Every organization
-- that uses Researcher (a member holds it, or a pending invitation offers it)
-- gets its own custom "Researcher" role with the same grants, and every
-- assignment and invitation moves to it, so nobody's permissions change.
-- Organizations that never used it get nothing.

ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS template_id          varchar(64),
    ADD COLUMN IF NOT EXISTS template_version     integer,
    ADD COLUMN IF NOT EXISTS template_permissions text[];

ALTER TABLE roles DROP CONSTRAINT IF EXISTS chk_roles_template_origin;
ALTER TABLE roles ADD CONSTRAINT chk_roles_template_origin CHECK (
    (template_id IS NULL AND template_version IS NULL AND template_permissions IS NULL)
    OR (template_id IS NOT NULL AND NOT is_system AND template_version >= 1 AND template_permissions IS NOT NULL)
);

COMMENT ON COLUMN roles.template_id IS 'Role template this custom role was created from (permission.RoleTemplates), NULL for a role built from scratch';
COMMENT ON COLUMN roles.template_version IS 'Template version the role was created from or last updated to';
COMMENT ON COLUMN roles.template_permissions IS 'The template''s permissions at template_version; compared with the current template to offer an update';

-- "researcher" is no longer a system slug.
-- expand-contract-ok: NOT VALID re-adds the same check minus one slug; existing rows are unaffected
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved;
ALTER TABLE roles ADD CONSTRAINT roles_custom_slug_not_reserved
    CHECK (is_system OR lower(btrim(slug)) !~ '^(owner|admin|member|viewer)$') NOT VALID;

-- One custom Researcher role per organization that uses the built-in one.
-- A custom role named "researcher" from before the slug was reserved keeps
-- its slug; the copy then takes "researcher-role".
INSERT INTO roles (id, tenant_id, slug, name, description, is_system, hierarchy_level,
                   has_full_data_access, template_id, template_version, template_permissions)
SELECT uuid_generate_v7(), u.tenant_id,
       CASE WHEN EXISTS (SELECT 1 FROM roles x WHERE x.tenant_id = u.tenant_id AND lower(x.slug) = 'researcher')
            THEN 'researcher-role' ELSE 'researcher' END,
       'Researcher',
       'Tests the bug-bounty programs the organization follows: programs, scans and findings of the programs whose team they belong to. Reports and discusses findings; cannot re-score severity, change the organization''s own scope or approve anything.',
       false, 30, false, 'researcher', 1,
       (SELECT array_agg(rp.permission_id ORDER BY rp.permission_id)
          FROM role_permissions rp WHERE rp.role_id = '00000000-0000-0000-0000-000000000005')
FROM (
    SELECT tenant_id FROM user_roles WHERE role_id = '00000000-0000-0000-0000-000000000005'
    UNION
    SELECT tenant_id FROM tenant_invitations WHERE '00000000-0000-0000-0000-000000000005'::uuid = ANY (role_ids)
) u
WHERE EXISTS (SELECT 1 FROM roles s WHERE s.id = '00000000-0000-0000-0000-000000000005')
  AND NOT EXISTS (SELECT 1 FROM roles c WHERE c.tenant_id = u.tenant_id AND c.template_id = 'researcher');

INSERT INTO role_permissions (role_id, permission_id)
SELECT c.id, rp.permission_id
FROM roles c
JOIN role_permissions rp ON rp.role_id = '00000000-0000-0000-0000-000000000005'
WHERE c.template_id = 'researcher' AND NOT c.is_system
  AND NOT EXISTS (SELECT 1 FROM role_permissions o WHERE o.role_id = c.id)
ON CONFLICT (role_id, permission_id) DO NOTHING;

UPDATE user_roles ur
SET role_id = c.id
FROM roles c
WHERE ur.role_id = '00000000-0000-0000-0000-000000000005'
  AND c.tenant_id = ur.tenant_id AND c.template_id = 'researcher' AND NOT c.is_system;

UPDATE tenant_invitations i
SET role_ids = array_replace(i.role_ids, '00000000-0000-0000-0000-000000000005'::uuid, c.id)
FROM roles c
WHERE '00000000-0000-0000-0000-000000000005'::uuid = ANY (i.role_ids)
  AND c.tenant_id = i.tenant_id AND c.template_id = 'researcher' AND NOT c.is_system;

-- The global row goes (its role_permissions rows cascade). Nothing references
-- it any more: group bindings only ever take custom roles.
DELETE FROM roles WHERE id = '00000000-0000-0000-0000-000000000005' AND is_system;
