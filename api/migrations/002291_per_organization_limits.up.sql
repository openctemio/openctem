-- Per-organization limits replace plans (docs/architecture/limits.md).
--
-- The core no longer knows plans. An organization has limits and feature
-- denies only where someone set them: the instance operator (origin
-- 'operator') or, on a hosted service, the control plane through the
-- internal API (origin 'control_plane'). No row means unlimited and allowed.
--
-- Data step: every organization keeps exactly the caps its plan gave it.
-- The plan's limits (the stored defaults, else the built-in Free defaults)
-- are written as operator limits with the reason "migrated from plan", and
-- modules the plan's module map left out become operator denies. Pro and
-- Enterprise had no limits and every module by default, so nothing is
-- written for them unless an administrator had narrowed them. Then plans,
-- plan defaults and the plan to module map are dropped.
--
-- Small tables (at most one row per organization and key). Stop the API
-- while this runs: it renames and drops tables the old code reads.

-- expand-contract-ok: contract step in the same release (owner rule: no release wait); the API stops for this migration (changelog upgrade note) and the new code reads only the new tables.

-- 1. Limits: tenant_plan_overrides becomes tenant_limits, with an origin.
ALTER TABLE tenant_plan_overrides RENAME TO tenant_limits;
ALTER TABLE tenant_limits RENAME CONSTRAINT tenant_plan_overrides_pkey TO tenant_limits_pkey;
ALTER TABLE tenant_limits RENAME CONSTRAINT tenant_plan_overrides_tenant_id_fkey TO tenant_limits_tenant_id_fkey;
ALTER TABLE tenant_limits RENAME CONSTRAINT chk_tenant_plan_overrides_reason TO chk_tenant_limits_reason;
ALTER TABLE tenant_limits RENAME CONSTRAINT chk_tenant_plan_overrides_value TO chk_tenant_limits_value;
ALTER TABLE tenant_limits ADD COLUMN origin text NOT NULL DEFAULT 'operator',
    ADD CONSTRAINT chk_tenant_limits_origin CHECK (origin IN ('operator', 'control_plane'));
ALTER TABLE tenant_limits DROP CONSTRAINT tenant_limits_pkey,
    ADD CONSTRAINT tenant_limits_pkey PRIMARY KEY (tenant_id, limit_key, origin);

-- The per-person organization cap was a property of the Free plan, never a
-- per-organization value: it is an instance setting now (orgs_per_user).
DELETE FROM tenant_limits WHERE limit_key = 'free_teams_per_user';

-- 2. The plan's limits as operator limits (an existing override wins).
WITH defaults AS (
    SELECT COALESCE(
        (SELECT value FROM platform_settings WHERE key = 'plan_limits'),
        '{"free":{"seats":5,"assets":500,"sensors":2,"api_keys":5,"ci_trusts":2,"invites_per_day":20,
          "platform_scans_per_day":10,"platform_scans_concurrent":1},"pro":{},"enterprise":{}}'::jsonb) AS d
), plans AS (
    SELECT t.id AS tenant_id, COALESCE(tp.plan, 'enterprise') AS plan
      FROM tenants t LEFT JOIN tenant_plans tp ON tp.tenant_id = t.id
)
INSERT INTO tenant_limits (tenant_id, limit_key, value, reason, origin, set_at)
SELECT p.tenant_id, kv.key, kv.value::int, 'migrated from plan', 'operator', now()
  FROM plans p, defaults, jsonb_each_text(COALESCE(defaults.d -> p.plan, '{}'::jsonb)) AS kv
 WHERE kv.key <> 'free_teams_per_user' AND kv.value::int >= 0
ON CONFLICT (tenant_id, limit_key, origin) DO NOTHING;

-- 3. Feature denies: tenant_module_grants becomes tenant_feature_denies.
--    Without plans every module is available, so a "grant" means nothing:
--    the plan's excluded modules become denies (unless granted), then the
--    grants go.
INSERT INTO tenant_module_grants (tenant_id, module_id, kind, reason, set_at)
SELECT t.id, m.id, 'deny', 'migrated from plan', now()
  FROM tenants t
  LEFT JOIN tenant_plans tp ON tp.tenant_id = t.id
  CROSS JOIN modules m
  CROSS JOIN (SELECT value AS pm FROM platform_settings WHERE key = 'plan_modules') s
 WHERE m.parent_module_id IS NULL AND NOT m.is_core
   AND NOT (COALESCE(s.pm -> COALESCE(tp.plan, 'enterprise'), '[]'::jsonb) ? '*')
   AND NOT (COALESCE(s.pm -> COALESCE(tp.plan, 'enterprise'), '[]'::jsonb) ? m.id)
ON CONFLICT (tenant_id, module_id) DO NOTHING;
DELETE FROM tenant_module_grants WHERE kind = 'grant';

ALTER TABLE tenant_module_grants RENAME TO tenant_feature_denies;
ALTER TABLE tenant_feature_denies RENAME COLUMN module_id TO feature;
ALTER TABLE tenant_feature_denies DROP CONSTRAINT chk_tenant_module_grants_kind, DROP COLUMN kind;
ALTER TABLE tenant_feature_denies DROP CONSTRAINT tenant_module_grants_module_id_fkey;
ALTER TABLE tenant_feature_denies RENAME CONSTRAINT tenant_module_grants_tenant_id_fkey TO tenant_feature_denies_tenant_id_fkey;
ALTER TABLE tenant_feature_denies RENAME CONSTRAINT chk_tenant_module_grants_reason TO chk_tenant_feature_denies_reason;
ALTER TABLE tenant_feature_denies ALTER COLUMN feature TYPE text;
ALTER TABLE tenant_feature_denies ADD COLUMN origin text NOT NULL DEFAULT 'operator',
    ADD CONSTRAINT chk_tenant_feature_denies_origin CHECK (origin IN ('operator', 'control_plane')),
    ADD CONSTRAINT chk_tenant_feature_denies_feature CHECK (feature ~ '^[a-z][a-z0-9_.-]{0,99}$');
ALTER TABLE tenant_feature_denies DROP CONSTRAINT tenant_module_grants_pkey,
    ADD CONSTRAINT tenant_feature_denies_pkey PRIMARY KEY (tenant_id, feature, origin);

-- 4. Contract: plans, plan defaults and the plan to module map.
DROP TABLE tenant_plans;
DELETE FROM platform_settings WHERE key IN ('plan_limits', 'plan_modules');
