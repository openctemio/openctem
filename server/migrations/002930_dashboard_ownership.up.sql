-- Dashboard ownership: organization and personal dashboards
-- (docs/architecture/dashboards.md, docs/rfcs/RFC-021-customizable-dashboards.md §11).
--
-- 1. user_dashboards gains a kind. A personal dashboard belongs to one user
--    (user_id); an organization dashboard belongs to the organization
--    (user_id NULL), has an order and at most one is the organization default.
--    Every row that exists today is personal.
-- 2. Every dashboard has a refresh schedule (NULL = the organization default)
--    and the bookkeeping the refresher needs (next_refresh_at, paused_at).
-- 3. dashboard_audience narrows an organization dashboard to roles or teams.
-- 4. Permissions: dashboards:org:view replaces dashboard:aggregate (every
--    holder is migrated, the change is audited and owners and admins get a
--    notice naming the members who gained it); dashboards:org:manage for
--    owners and admins.

-- 1. Kind, order, organization default ----------------------------------------
ALTER TABLE user_dashboards
    ADD COLUMN kind text NOT NULL DEFAULT 'personal',
    ADD COLUMN position integer NOT NULL DEFAULT 0,
    ADD COLUMN is_org_default boolean NOT NULL DEFAULT false,
    ADD COLUMN refresh_schedule text,
    ADD COLUMN refresh_daily_minute smallint,
    ADD COLUMN next_refresh_at timestamptz,
    ADD COLUMN paused_at timestamptz,
    ADD COLUMN template_version integer,
    ADD COLUMN origin text NOT NULL DEFAULT 'user';

ALTER TABLE user_dashboards ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE user_dashboards
    ADD CONSTRAINT chk_user_dashboards_kind CHECK (kind IN ('personal', 'organization')),
    ADD CONSTRAINT chk_user_dashboards_owner CHECK ((kind = 'personal') = (user_id IS NOT NULL)),
    ADD CONSTRAINT chk_user_dashboards_personal_default CHECK (NOT is_default OR kind = 'personal'),
    ADD CONSTRAINT chk_user_dashboards_org_default CHECK (NOT is_org_default OR kind = 'organization'),
    ADD CONSTRAINT chk_user_dashboards_schedule CHECK (
        refresh_schedule IS NULL OR refresh_schedule IN ('manual', '5m', '15m', '1h', '6h', 'daily')),
    ADD CONSTRAINT chk_user_dashboards_daily_minute CHECK (
        (refresh_schedule = 'daily' AND refresh_daily_minute BETWEEN 0 AND 1439)
        OR (refresh_schedule IS DISTINCT FROM 'daily' AND refresh_daily_minute IS NULL)),
    ADD CONSTRAINT chk_user_dashboards_origin CHECK (origin IN ('user', 'builtin', 'duplicated', 'shared'));

-- Names: unique per user for personal dashboards (existing index, user_id is
-- NULL for organization rows so they never collide there) and unique per
-- organization for organization dashboards.
CREATE UNIQUE INDEX uq_user_dashboards_org_name
    ON user_dashboards (tenant_id, name) WHERE kind = 'organization';
CREATE UNIQUE INDEX uq_user_dashboards_one_org_default
    ON user_dashboards (tenant_id) WHERE is_org_default;
CREATE INDEX idx_user_dashboards_org_position
    ON user_dashboards (tenant_id, position) WHERE kind = 'organization';

COMMENT ON COLUMN user_dashboards.kind IS 'personal (owned by user_id, computed for the owner''s data scope) or organization (owned by the organization, user_id NULL, needs dashboards:org:view)';
COMMENT ON COLUMN user_dashboards.refresh_schedule IS 'manual, 5m, 15m, 1h, 6h or daily; NULL = the organization default. Never below the edition floor (limit dashboard_refresh_floor_minutes)';
COMMENT ON COLUMN user_dashboards.refresh_daily_minute IS 'Minute of the day (UTC) of a daily refresh';
COMMENT ON COLUMN user_dashboards.origin IS 'user, builtin (seeded template), duplicated (copy of an organization dashboard) or shared (copy of a layout another member shared)';

-- 2. Audience of an organization dashboard ------------------------------------
CREATE TABLE dashboard_audience (
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dashboard_id   uuid NOT NULL REFERENCES user_dashboards(id) ON DELETE CASCADE,
    principal_type text NOT NULL CHECK (principal_type IN ('role', 'group')),
    principal_id   uuid NOT NULL,
    created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (dashboard_id, principal_type, principal_id)
);
CREATE INDEX idx_dashboard_audience_tenant ON dashboard_audience (tenant_id, dashboard_id);
COMMENT ON TABLE dashboard_audience IS
    'Roles or teams an organization dashboard is narrowed to. No rows: every dashboards:org:view holder sees it. A row never widens access: the viewer still needs dashboards:org:view.';

-- 3. Permissions --------------------------------------------------------------
-- dashboards:org:view is dashboard:aggregate renamed (old id, new id):
INSERT INTO permissions (id, module_id, name, description, is_active)
SELECT r.new_id, 'dashboard', r.name, r.description, true
  FROM (VALUES
    ('dashboard:aggregate', 'dashboards:org:view', 'View Organization Dashboards',
     'See organization dashboards: organization-wide numbers and the names in their lists, whatever your own data scope')
  ) AS r(old_id, new_id, name, description)
ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('dashboards:org:manage', 'dashboard', 'Manage Organization Dashboards',
     'Create, edit, order, delete organization dashboards and set their default, audience and refresh schedule', true)
ON CONFLICT (id) DO NOTHING;

-- Who gains organization view through a custom role, recorded before the
-- grants move (owners and admins hold it through their built-in roles).
CREATE TEMP TABLE dash_org_view_migrated AS
SELECT r.tenant_id, r.id AS role_id, r.name AS role_name
  FROM roles r
  JOIN role_permissions rp ON rp.role_id = r.id AND rp.permission_id = 'dashboard:aggregate'
 WHERE r.tenant_id IS NOT NULL;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'dashboards:org:view'
  FROM role_permissions rp
 WHERE rp.permission_id = 'dashboard:aggregate'
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'dashboards:org:manage'
  FROM roles r
 WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- The program-lead template (v2) carries the new name; custom roles taken
-- from v1 hold the same grants, so they move to v2 with it.
UPDATE roles
   SET template_permissions = array_replace(template_permissions, 'dashboard:aggregate', 'dashboards:org:view'),
       template_version = CASE WHEN template_id = 'program-lead' AND template_version = 1 THEN 2 ELSE template_version END
 WHERE template_permissions @> ARRAY['dashboard:aggregate'];

UPDATE api_keys
   SET scopes = array_replace(scopes, 'dashboard:aggregate', 'dashboards:org:view')
 WHERE scopes @> ARRAY['dashboard:aggregate'];

-- One audit row per migrated custom role, naming the members who hold it.
INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, resource_name, changes, severity, message, metadata)
SELECT m.tenant_id, 'role.permission_migrated', 'role', m.role_id::text, m.role_name,
       jsonb_build_object('permissions', jsonb_build_object('old', 'dashboard:aggregate', 'new', 'dashboards:org:view')),
       'high',
       'Organization totals became organization dashboards: this role now shows organization dashboards, including the names in their lists',
       jsonb_build_object('source', 'migration', 'members', COALESCE((
           SELECT jsonb_agg(DISTINCT g.user_id::text)
             FROM v_user_role_grants g
            WHERE g.tenant_id = m.tenant_id AND g.role_id = m.role_id), '[]'::jsonb))
  FROM dash_org_view_migrated m;

-- A one-time notice to every active owner and administrator of an
-- organization where members gained organization view through a custom role.
WITH gained AS (
    SELECT g.tenant_id, array_agg(DISTINCT COALESCE(NULLIF(u.name, ''), u.email) ORDER BY COALESCE(NULLIF(u.name, ''), u.email)) AS names
      FROM dash_org_view_migrated m
      JOIN v_user_role_grants g ON g.tenant_id = m.tenant_id AND g.role_id = m.role_id
      JOIN users u ON u.id = g.user_id
      JOIN tenant_members tm ON tm.tenant_id = g.tenant_id AND tm.user_id = g.user_id AND tm.status = 'active'
     GROUP BY g.tenant_id
)
INSERT INTO notifications (tenant_id, audience, audience_id, notification_type, title, body, severity, url)
SELECT tm.tenant_id, 'user', tm.user_id, 'access_changed',
       'Organization dashboards: members who can now see organization-wide names',
       'The "View Organization Totals" permission became "View Organization Dashboards". Its holders now see '
       || 'organization dashboards, including the names of findings and assets in their lists. Members who hold it '
       || 'through a custom role: '
       || array_to_string(gained.names[1:50], ', ')
       || CASE WHEN cardinality(gained.names) > 50 THEN format(' and %s more', cardinality(gained.names) - 50) ELSE '' END
       || '. Review the roles under Settings > Roles.',
       'medium', '/settings/roles'
  FROM gained
  JOIN tenant_members tm ON tm.tenant_id = gained.tenant_id AND tm.role IN ('owner', 'admin') AND tm.status = 'active';

DELETE FROM role_permissions WHERE permission_id = 'dashboard:aggregate';
DELETE FROM permissions WHERE id = 'dashboard:aggregate';

-- expand-contract-ok: the only DROP is dash_org_view_migrated, a session TEMP
-- table created above; no release reads it. Old pods checking dashboard:aggregate
-- during the rollout fail closed (organization totals hidden until they restart).
DROP TABLE dash_org_view_migrated;
