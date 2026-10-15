-- Restores the plan tables' shape. Plans themselves are not recoverable:
-- every organization comes back without a plan row (unlimited), with its
-- operator limits as overrides and its operator denies as deny grants.
-- Control-plane rows are dropped.

CREATE TABLE tenant_plans (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    plan       text NOT NULL,
    updated_by uuid,
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_tenant_plans_plan CHECK (plan IN ('free', 'pro', 'enterprise'))
);

DELETE FROM tenant_feature_denies WHERE origin <> 'operator' OR feature NOT IN (SELECT id FROM modules);
ALTER TABLE tenant_feature_denies DROP CONSTRAINT tenant_feature_denies_pkey,
    DROP CONSTRAINT chk_tenant_feature_denies_origin, DROP CONSTRAINT chk_tenant_feature_denies_feature, DROP COLUMN origin;
ALTER TABLE tenant_feature_denies ALTER COLUMN feature TYPE character varying(50);
ALTER TABLE tenant_feature_denies RENAME COLUMN feature TO module_id;
ALTER TABLE tenant_feature_denies ADD COLUMN kind text NOT NULL DEFAULT 'deny',
    ADD CONSTRAINT chk_tenant_module_grants_kind CHECK (kind IN ('grant', 'deny'));
ALTER TABLE tenant_feature_denies ALTER COLUMN kind DROP DEFAULT;
ALTER TABLE tenant_feature_denies ADD CONSTRAINT tenant_module_grants_pkey PRIMARY KEY (tenant_id, module_id),
    ADD CONSTRAINT tenant_module_grants_module_id_fkey FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE;
ALTER TABLE tenant_feature_denies RENAME CONSTRAINT tenant_feature_denies_tenant_id_fkey TO tenant_module_grants_tenant_id_fkey;
ALTER TABLE tenant_feature_denies RENAME CONSTRAINT chk_tenant_feature_denies_reason TO chk_tenant_module_grants_reason;
ALTER TABLE tenant_feature_denies RENAME TO tenant_module_grants;

DELETE FROM tenant_limits WHERE origin <> 'operator';
ALTER TABLE tenant_limits DROP CONSTRAINT tenant_limits_pkey,
    DROP CONSTRAINT chk_tenant_limits_origin, DROP COLUMN origin;
ALTER TABLE tenant_limits ADD CONSTRAINT tenant_plan_overrides_pkey PRIMARY KEY (tenant_id, limit_key);
ALTER TABLE tenant_limits RENAME CONSTRAINT tenant_limits_tenant_id_fkey TO tenant_plan_overrides_tenant_id_fkey;
ALTER TABLE tenant_limits RENAME CONSTRAINT chk_tenant_limits_reason TO chk_tenant_plan_overrides_reason;
ALTER TABLE tenant_limits RENAME CONSTRAINT chk_tenant_limits_value TO chk_tenant_plan_overrides_value;
ALTER TABLE tenant_limits RENAME TO tenant_plan_overrides;

DELETE FROM platform_settings WHERE key = 'self_service_default_limits';
