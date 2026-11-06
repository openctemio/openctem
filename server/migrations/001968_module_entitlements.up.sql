-- Module entitlements (RFC-064): which modules an organization may use.
--
-- The plan decides first: platform_settings 'plan_modules' maps each plan to
-- the modules it includes. Nothing is stored until an administrator narrows
-- it, and until then every plan includes every module, so this migration
-- changes nothing for any organization.
--
-- tenant_module_grants: a platform administrator's change for one
-- organization: 'grant' adds a module its plan does not include (a trial, an
-- add-on), 'deny' removes one its plan includes. A reason is required; an
-- expiry is optional.
--
-- The organization-chosen product bundles (tenants.settings
-- 'subscribed_bundles') are retired: packaging is the plan's and the
-- administrator's, not the organization's. No organization had one.

CREATE TABLE tenant_module_grants (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    module_id  character varying(50) NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    kind       text NOT NULL,
    reason     text NOT NULL,
    expires_at timestamp with time zone,
    set_by     uuid,
    set_at     timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, module_id),
    CONSTRAINT chk_tenant_module_grants_kind CHECK (kind IN ('grant', 'deny')),
    CONSTRAINT chk_tenant_module_grants_reason CHECK (char_length(reason) BETWEEN 1 AND 500)
);

UPDATE tenants SET settings = settings - 'subscribed_bundles'
 WHERE settings IS NOT NULL AND jsonb_exists(settings, 'subscribed_bundles');
