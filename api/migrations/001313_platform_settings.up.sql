-- Platform-level settings edited in the admin console. The first one is the
-- sign-up policy (key 'signup_policy'): who may create an organization
-- (docs/architecture/user-onboarding.md, "Sign-up policy"). Not tenant data:
-- the table has no tenant_id and only the console writes it.
--
-- version: optimistic concurrency (the console sends the version it read).
-- source: 'environment' when seeded from the environment at first start,
-- 'console' once an administrator saved it.
-- A new, empty table; the API seeds the sign-up policy at start-up.

CREATE TABLE platform_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    version    integer NOT NULL DEFAULT 1,
    source     text NOT NULL DEFAULT 'console',
    updated_by uuid,
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_platform_settings_source CHECK (source IN ('environment', 'console')),
    CONSTRAINT chk_platform_settings_value_size CHECK (octet_length(value::text) <= 8192)
);
