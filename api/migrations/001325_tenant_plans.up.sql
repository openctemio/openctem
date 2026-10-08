-- Plans and limits (docs/architecture/plans-and-limits.md).
--
-- tenant_plans: an organization's plan. An organization without a row was
-- created before plans and counts as Enterprise (no limits), so this
-- migration changes nothing for existing organizations. New self-service
-- organizations get 'free'.
-- tenant_plan_overrides: a limit a platform administrator set for one
-- organization (wins over the plan default), with a reason and an optional
-- expiry.
-- Plan defaults live in platform_settings under 'plan_limits'.
-- New, empty tables.

CREATE TABLE tenant_plans (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    plan       text NOT NULL,
    updated_by uuid,
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_tenant_plans_plan CHECK (plan IN ('free', 'pro', 'enterprise'))
);

CREATE TABLE tenant_plan_overrides (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    limit_key  text NOT NULL,
    value      integer NOT NULL,
    reason     text NOT NULL,
    expires_at timestamp with time zone,
    set_by     uuid,
    set_at     timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, limit_key),
    CONSTRAINT chk_tenant_plan_overrides_value CHECK (value >= -1),
    CONSTRAINT chk_tenant_plan_overrides_reason CHECK (char_length(reason) BETWEEN 1 AND 500)
);
