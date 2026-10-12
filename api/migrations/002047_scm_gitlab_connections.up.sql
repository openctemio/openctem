-- GitLab group access tokens an organization stores to post the CI gate as a
-- commit status and a merge request note (RFC-077). The token is encrypted
-- with the application key; it never leaves the API.
CREATE TABLE IF NOT EXISTS scm_gitlab_connections (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host                  VARCHAR(255) NOT NULL,
    group_path            VARCHAR(500) NOT NULL,
    group_id              BIGINT NOT NULL,
    token_encrypted       TEXT NOT NULL,
    token_user_id         BIGINT NOT NULL DEFAULT 0,
    token_expires_at      DATE,
    status                VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by            UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_scm_gitlab_connections_status CHECK (status IN ('active', 'failing')),
    CONSTRAINT uq_scm_gitlab_connections_group UNIQUE (tenant_id, host, group_id)
);
CREATE INDEX IF NOT EXISTS idx_scm_gitlab_connections_tenant ON scm_gitlab_connections (tenant_id, host);
