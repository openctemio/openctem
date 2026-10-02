-- =============================================================================
-- Migration 245: team role from the system role IDs only
-- =============================================================================
-- v_user_effective_role is the oracle for a user's team role: the token's role
-- and admin flag, RequireTeamAdmin/RequireTeamOwner and IsOwner all read it
-- (through TenantRepository). It returned the slug of the user's highest
-- hierarchy_level role in user_roles, which could be a custom role. Custom
-- roles could take any slug, including 'owner', and any level up to 100, so a
-- holder of team:roles:write + team:roles:assign could make themselves owner.
--
-- From here on:
--   * the team role is the highest of the four SYSTEM roles the user holds,
--     matched by role id, never by slug or hierarchy_level;
--   * a member with no system role gets the membership label, except that the
--     label never makes anyone owner or admin (an owner/admin label without the
--     matching system role resolves to 'viewer');
--   * custom roles may not use a system slug or rank at or above admin (80).
--
-- The view keeps its columns and their types (CREATE OR REPLACE), and it now
-- has one row per membership, so the COALESCE fallbacks in the queries that
-- LEFT JOIN it no longer decide anything.

CREATE OR REPLACE VIEW v_user_effective_role AS
SELECT
    m.user_id,
    m.tenant_id,
    COALESCE(
        sr.slug,
        CASE WHEN m.role IN ('member', 'viewer') THEN m.role ELSE 'viewer' END
    )::VARCHAR(50) AS role,
    sr.name AS role_name,
    sr.hierarchy_level,
    COALESCE(sr.has_full_data_access, FALSE) AS has_full_data_access
FROM tenant_members m
LEFT JOIN LATERAL (
    SELECT
        (CASE r.id
            WHEN '00000000-0000-0000-0000-000000000001' THEN 'owner'
            WHEN '00000000-0000-0000-0000-000000000002' THEN 'admin'
            WHEN '00000000-0000-0000-0000-000000000003' THEN 'member'
            ELSE 'viewer'
        END)::VARCHAR(50) AS slug,
        r.name,
        r.hierarchy_level,
        r.has_full_data_access
    FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.user_id = m.user_id
      AND ur.tenant_id = m.tenant_id
      AND r.id IN (
          '00000000-0000-0000-0000-000000000001',
          '00000000-0000-0000-0000-000000000002',
          '00000000-0000-0000-0000-000000000003',
          '00000000-0000-0000-0000-000000000004'
      )
    ORDER BY CASE r.id
        WHEN '00000000-0000-0000-0000-000000000001' THEN 4
        WHEN '00000000-0000-0000-0000-000000000002' THEN 3
        WHEN '00000000-0000-0000-0000-000000000003' THEN 2
        ELSE 1
    END DESC
    LIMIT 1
) sr ON TRUE;

COMMENT ON VIEW v_user_effective_role IS
    'Team role per membership: the highest SYSTEM role held (by role id), else the membership label capped at member. Custom roles never count.';

-- Existing custom roles that took a system slug are renamed to custom-<slug>
-- (with an id suffix when that is taken or when two of them map to the same
-- name). Their permissions and assignments are unchanged; only the slug moves.
WITH reserved AS (
    SELECT
        r.id,
        r.tenant_id,
        'custom-' || lower(btrim(r.slug)) AS base,
        row_number() OVER (PARTITION BY r.tenant_id, lower(btrim(r.slug)) ORDER BY r.created_at, r.id) AS rn
    FROM roles r
    WHERE NOT r.is_system
      AND lower(btrim(r.slug)) IN ('owner', 'admin', 'member', 'viewer')
)
UPDATE roles r
SET slug = CASE
        WHEN x.rn = 1 AND NOT EXISTS (
            SELECT 1 FROM roles o
            WHERE o.tenant_id IS NOT DISTINCT FROM x.tenant_id AND o.slug = x.base
        ) THEN x.base
        ELSE x.base || '-' || left(r.id::text, 8)
    END,
    updated_at = NOW()
FROM reserved x
WHERE r.id = x.id;

-- Custom roles rank below admin. hierarchy_level no longer decides any access
-- (see the view above); this only keeps the stored value honest.
UPDATE roles
SET hierarchy_level = 79, updated_at = NOW()
WHERE NOT is_system
  AND hierarchy_level > 79;

ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved;
ALTER TABLE roles ADD CONSTRAINT roles_custom_slug_not_reserved
    CHECK (is_system OR lower(btrim(slug)) !~ '^(owner|admin|member|viewer)$');

ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_level_below_admin;
ALTER TABLE roles ADD CONSTRAINT roles_custom_level_below_admin
    CHECK (is_system OR hierarchy_level < 80);

COMMENT ON COLUMN roles.hierarchy_level IS
    'Display/sort order only. System: owner=100, admin=80, member=50, viewer=20. Custom roles are below 80. Never used to decide the team role.';
