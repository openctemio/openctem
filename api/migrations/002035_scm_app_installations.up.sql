-- Code-host app installations an organization binds to post CI checks and
-- pull request comments (RFC-077). One installation belongs to at most one
-- tenant.
CREATE TABLE IF NOT EXISTS scm_app_installations (
    id                   UUID PRIMARY KEY,
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider             VARCHAR(20) NOT NULL,
    installation_id      BIGINT NOT NULL,
    account_login        VARCHAR(255) NOT NULL,
    account_id           BIGINT NOT NULL DEFAULT 0,
    account_type         VARCHAR(20) NOT NULL DEFAULT '',
    repository_selection VARCHAR(20) NOT NULL DEFAULT '',
    status               VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_scm_app_installations_provider CHECK (provider IN ('github')),
    CONSTRAINT chk_scm_app_installations_status CHECK (status IN ('active', 'suspended', 'deleted')),
    CONSTRAINT uq_scm_app_installations_installation UNIQUE (provider, installation_id),
    CONSTRAINT uq_scm_app_installations_tenant_id UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_scm_app_installations_tenant ON scm_app_installations (tenant_id, provider, lower(account_login));
