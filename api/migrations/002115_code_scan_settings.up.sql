-- Platform code scanning: a baseline of each repository's protected branches
-- before CI runs are judged on diffs, and periodic full rescans of those
-- branches on a sensor. Design: research/127 §6, docs/rfcs/RFC-091-code-scanning-baseline.md.
--
-- code_scan_settings: one tenant template (repository_asset_id NULL) and
-- per-repository overrides. Small (one row per repository at most); the new
-- repository_branches columns have constant defaults (no table rewrite).
CREATE TABLE code_scan_settings (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    repository_asset_id UUID,
    protected_branches  TEXT[] NOT NULL DEFAULT ARRAY['{default}', 'develop'],
    capabilities        TEXT[] NOT NULL DEFAULT ARRAY['sast', 'secrets', 'sca', 'iac'],
    schedule            VARCHAR(16) NOT NULL DEFAULT 'weekly',
    routing             VARCHAR(16) NOT NULL DEFAULT 'auto',
    enabled             BOOLEAN NOT NULL DEFAULT true,
    updated_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_code_scan_settings_repository FOREIGN KEY (tenant_id, repository_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_code_scan_settings_scope UNIQUE NULLS NOT DISTINCT (tenant_id, repository_asset_id),
    CONSTRAINT chk_code_scan_settings_schedule CHECK (schedule IN ('off', 'daily', 'weekly', 'monthly')),
    CONSTRAINT chk_code_scan_settings_routing CHECK (routing IN ('auto', 'platform', 'tenant')),
    CONSTRAINT chk_code_scan_settings_branches CHECK (cardinality(protected_branches) BETWEEN 1 AND 20),
    CONSTRAINT chk_code_scan_settings_capabilities CHECK (
        cardinality(capabilities) BETWEEN 1 AND 4
        AND capabilities <@ ARRAY['sast', 'secrets', 'sca', 'iac']::TEXT[])
);

COMMENT ON TABLE code_scan_settings IS
    'Code scanning of repositories: the tenant template (repository_asset_id NULL) and per-repository overrides.';
COMMENT ON COLUMN code_scan_settings.protected_branches IS
    'Branch names or glob patterns ("release/*") scanned in full; "{default}" is the repository''s default branch.';

-- The baseline of a protected branch and its latest full scan.
ALTER TABLE repository_branches
    ADD COLUMN baseline_state VARCHAR(16) NOT NULL DEFAULT 'none',
    ADD COLUMN baseline_commit VARCHAR(64),
    ADD COLUMN baseline_at TIMESTAMPTZ,
    ADD COLUMN baseline_error TEXT,
    ADD COLUMN last_full_scan_at TIMESTAMPTZ,
    ADD COLUMN last_full_scan_trigger VARCHAR(16),
    ADD CONSTRAINT chk_repository_branches_baseline_state
        CHECK (baseline_state IN ('none', 'queued', 'running', 'done', 'failed')),
    ADD CONSTRAINT chk_repository_branches_full_scan_trigger
        CHECK (last_full_scan_trigger IS NULL
            OR last_full_scan_trigger IN ('baseline', 'schedule', 'rules', 'manual', 'stale'));

COMMENT ON COLUMN repository_branches.baseline_state IS
    'none: never scanned in full; queued/running: a full scan is pending; done: baseline_commit is the last full scan; failed: see baseline_error.';
