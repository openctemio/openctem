-- scope_provider_keeps: an organization's decision to keep scanning a scope
-- entry that names a provider's shared addresses (an address, CIDR or range
-- wholly inside a range the provider publishes for a front end many
-- organizations share; docs/architecture/provider-shared-addresses.md). A
-- kept entry leaves the Scope page's provider addresses card and is never
-- held by the hold_provider_entries setting. Moving entries out of scope
-- writes no row here: the entry is deactivated and an exclusion created.
CREATE TABLE IF NOT EXISTS scope_provider_keeps (
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id       UUID        NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    -- The provider the entry was classified under, and the classifier's
    -- dataset version at the time (pkg/domain/edgeaddr).
    provider        TEXT        NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 100),
    dataset_version TEXT        NOT NULL DEFAULT '' CHECK (char_length(dataset_version) <= 50),
    decided_by      TEXT        NOT NULL DEFAULT '' CHECK (char_length(decided_by) <= 200),
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_scope_provider_keeps_target ON scope_provider_keeps (target_id);

COMMENT ON TABLE scope_provider_keeps IS
    'Scope entries on a provider''s shared addresses that the organization chose to keep scanning.';
