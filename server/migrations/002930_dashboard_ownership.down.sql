-- Reverts 002930_dashboard_ownership. Organization dashboards cannot be
-- expressed without a kind, so they are removed; personal dashboards stay.
-- The audit rows and notices the up migration wrote are history and stay.

INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('dashboard:aggregate', 'dashboard', 'View Organization Totals',
     'See organization-wide dashboard totals even with a restricted data scope (breakdowns under 5 are hidden)', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'dashboard:aggregate'
  FROM role_permissions rp
 WHERE rp.permission_id = 'dashboards:org:view'
ON CONFLICT (role_id, permission_id) DO NOTHING;

UPDATE roles
   SET template_permissions = array_replace(template_permissions, 'dashboards:org:view', 'dashboard:aggregate'),
       template_version = CASE WHEN template_id = 'program-lead' AND template_version = 2 THEN 1 ELSE template_version END
 WHERE template_permissions @> ARRAY['dashboards:org:view'];

UPDATE roles
   SET template_permissions = array_remove(template_permissions, 'dashboards:org:manage')
 WHERE template_permissions @> ARRAY['dashboards:org:manage'];

UPDATE api_keys
   SET scopes = array_replace(scopes, 'dashboards:org:view', 'dashboard:aggregate')
 WHERE scopes @> ARRAY['dashboards:org:view'];

UPDATE api_keys
   SET scopes = array_remove(scopes, 'dashboards:org:manage')
 WHERE scopes @> ARRAY['dashboards:org:manage'];

DELETE FROM role_permissions WHERE permission_id IN ('dashboards:org:view', 'dashboards:org:manage');
DELETE FROM permissions WHERE id IN ('dashboards:org:view', 'dashboards:org:manage');

DROP TABLE IF EXISTS dashboard_audience;

DELETE FROM user_dashboards WHERE kind = 'organization';

DROP INDEX IF EXISTS idx_user_dashboards_org_position;
DROP INDEX IF EXISTS uq_user_dashboards_one_org_default;
DROP INDEX IF EXISTS uq_user_dashboards_org_name;

ALTER TABLE user_dashboards
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_origin,
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_daily_minute,
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_schedule,
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_org_default,
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_personal_default,
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_owner,
    DROP CONSTRAINT IF EXISTS chk_user_dashboards_kind;

ALTER TABLE user_dashboards ALTER COLUMN user_id SET NOT NULL;

ALTER TABLE user_dashboards
    DROP COLUMN IF EXISTS origin,
    DROP COLUMN IF EXISTS template_version,
    DROP COLUMN IF EXISTS paused_at,
    DROP COLUMN IF EXISTS next_refresh_at,
    DROP COLUMN IF EXISTS refresh_daily_minute,
    DROP COLUMN IF EXISTS refresh_schedule,
    DROP COLUMN IF EXISTS is_org_default,
    DROP COLUMN IF EXISTS position,
    DROP COLUMN IF EXISTS kind;
