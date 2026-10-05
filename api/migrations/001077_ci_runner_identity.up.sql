-- CI runner identity and the central gate (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
--
-- A CI job proves who it is with its provider's OIDC token (GitHub Actions,
-- GitLab CI) and exchanges it for a short-lived upload token bound to one run
-- on one repository asset. A run is not a sensor: it has no sensor row, no
-- heartbeat and no offline alert.
--
--   ci_trust_configs   per-tenant trust: issuer, audience, claim rules
--   ci_runs            one row per exchanged pipeline run (repository, commit,
--                      branch, pull request, pipeline URL, actor) and its
--                      upload token's hash; the verdict once evaluated
--   ci_run_findings    the findings a run reported (server fingerprints), for
--                      the gate
--   ci_oidc_replay     OIDC token ids already exchanged (replay protection);
--                      keyed by issuer, not tenant: one token is good for one
--                      exchange anywhere
--   ci_gate_policies   gate policy per tenant, business unit or repository
--   ci_gate_overrides  break-glass: one commit of one repository passes the
--                      gate until it expires; every use is audited
--
-- Permissions: scans:ci:read (runs, trust configs, policies), scans:ci:write
-- (trust configs and policies) and scans:ci:override (break-glass). The two
-- write permissions issue or bypass credentials and controls, so they are
-- admin-only: the trigger from migration 000945 now refuses them on custom
-- roles too.
--
-- Live impact: new tables only, plus three permission rows and their grants
-- to the owner and admin system roles. No existing row changes.

CREATE TABLE IF NOT EXISTS ci_trust_configs (
    id             UUID         PRIMARY KEY,
    tenant_id      UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name           VARCHAR(200) NOT NULL,
    provider       VARCHAR(20)  NOT NULL,
    issuer         VARCHAR(500) NOT NULL,
    audience       VARCHAR(500) NOT NULL,
    rules          JSONB        NOT NULL DEFAULT '{}'::jsonb,
    default_branch VARCHAR(255) NOT NULL DEFAULT 'main',
    enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by     UUID         REFERENCES users(id) ON DELETE SET NULL,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_ci_trust_configs_provider CHECK (provider IN ('github', 'gitlab')),
    CONSTRAINT chk_ci_trust_configs_rules CHECK (jsonb_typeof(rules) = 'object'),
    CONSTRAINT uq_ci_trust_configs_name UNIQUE (tenant_id, name),
    CONSTRAINT uq_ci_trust_configs_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ci_trust_configs_lookup
    ON ci_trust_configs (tenant_id, issuer) WHERE enabled;

COMMENT ON TABLE ci_trust_configs IS
    'Which CI pipelines may exchange their OIDC token for a run upload token (RFC-051).';

CREATE TABLE IF NOT EXISTS ci_runs (
    id                  UUID          PRIMARY KEY,
    tenant_id           UUID          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    trust_config_id     UUID          REFERENCES ci_trust_configs(id) ON DELETE SET NULL,
    repository_asset_id UUID          NOT NULL,
    provider            VARCHAR(20)   NOT NULL,
    issuer              VARCHAR(500)  NOT NULL,
    repository          VARCHAR(500)  NOT NULL,
    ref                 VARCHAR(500)  NOT NULL DEFAULT '',
    branch              VARCHAR(255)  NOT NULL DEFAULT '',
    commit_sha          VARCHAR(64)   NOT NULL DEFAULT '',
    pull_request        VARCHAR(32)   NOT NULL DEFAULT '',
    default_branch      VARCHAR(255)  NOT NULL DEFAULT '',
    is_default_branch   BOOLEAN       NOT NULL DEFAULT FALSE,
    event               VARCHAR(64)   NOT NULL DEFAULT '',
    environment         VARCHAR(255)  NOT NULL DEFAULT '',
    actor               VARCHAR(255)  NOT NULL DEFAULT '',
    external_run_id     VARCHAR(64)   NOT NULL DEFAULT '',
    run_attempt         VARCHAR(16)   NOT NULL DEFAULT '',
    workflow            VARCHAR(500)  NOT NULL DEFAULT '',
    pipeline_url        VARCHAR(1000) NOT NULL DEFAULT '',
    fork                BOOLEAN       NOT NULL DEFAULT FALSE,
    token_hash          BYTEA,
    token_expires_at    TIMESTAMPTZ,
    status              VARCHAR(20)   NOT NULL DEFAULT 'running',
    verdict             VARCHAR(10),
    verdict_detail      JSONB,
    evaluated_at        TIMESTAMPTZ,
    reports_count       INT           NOT NULL DEFAULT 0,
    findings_count      INT           NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ci_runs_asset FOREIGN KEY (tenant_id, repository_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ci_runs_status CHECK (status IN ('running', 'evaluated')),
    CONSTRAINT chk_ci_runs_verdict CHECK (verdict IS NULL OR verdict IN ('pass', 'fail')),
    CONSTRAINT uq_ci_runs_tenant_id UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ci_runs_token_hash
    ON ci_runs (token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ci_runs_tenant_created
    ON ci_runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ci_runs_tenant_asset
    ON ci_runs (tenant_id, repository_asset_id, created_at DESC);

COMMENT ON TABLE ci_runs IS
    'CI pipeline runs (RFC-051). Not sensors: no fleet row, no heartbeat. token_hash is the SHA-256 of the run''s upload token; the token itself is never stored.';

CREATE TABLE IF NOT EXISTS ci_run_findings (
    tenant_id   UUID         NOT NULL,
    run_id      UUID         NOT NULL,
    fingerprint VARCHAR(512) NOT NULL,
    PRIMARY KEY (run_id, fingerprint),
    CONSTRAINT fk_ci_run_findings_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES ci_runs(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ci_oidc_replay (
    issuer     VARCHAR(500) NOT NULL,
    jti        VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (issuer, jti)
);

CREATE INDEX IF NOT EXISTS idx_ci_oidc_replay_expires ON ci_oidc_replay (expires_at);

COMMENT ON TABLE ci_oidc_replay IS
    'OIDC token ids already exchanged for a CI upload token (RFC-051). Global by design: a token is good for one exchange.';

CREATE TABLE IF NOT EXISTS ci_gate_policies (
    id                UUID         PRIMARY KEY,
    tenant_id         UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_type        VARCHAR(20)  NOT NULL,
    scope_id          UUID,
    enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    mode              VARCHAR(10)  NOT NULL DEFAULT 'enforce',
    fail_on_severity  VARCHAR(10)  NOT NULL DEFAULT 'high',
    new_findings_only BOOLEAN      NOT NULL DEFAULT TRUE,
    fail_on_kev       BOOLEAN      NOT NULL DEFAULT TRUE,
    epss_threshold    NUMERIC(5,4),
    created_by        UUID         REFERENCES users(id) ON DELETE SET NULL,
    updated_by        UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_ci_gate_policies_scope CHECK (
        scope_type IN ('tenant', 'business_unit', 'repository')
        AND ((scope_type = 'tenant') = (scope_id IS NULL))),
    CONSTRAINT chk_ci_gate_policies_mode CHECK (mode IN ('enforce', 'warn')),
    CONSTRAINT chk_ci_gate_policies_severity CHECK (fail_on_severity IN ('critical', 'high', 'medium', 'low', 'none')),
    CONSTRAINT chk_ci_gate_policies_epss CHECK (epss_threshold IS NULL OR (epss_threshold >= 0 AND epss_threshold <= 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ci_gate_policies_scope
    ON ci_gate_policies (tenant_id, scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE IF NOT EXISTS ci_gate_overrides (
    id                  UUID         PRIMARY KEY,
    tenant_id           UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    repository_asset_id UUID         NOT NULL,
    commit_sha          VARCHAR(64)  NOT NULL,
    reason              TEXT         NOT NULL,
    created_by          UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_by_email    VARCHAR(320) NOT NULL DEFAULT '',
    expires_at          TIMESTAMPTZ  NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_by          UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ci_gate_overrides_asset FOREIGN KEY (tenant_id, repository_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ci_gate_overrides_reason CHECK (char_length(reason) BETWEEN 10 AND 2000)
);

CREATE INDEX IF NOT EXISTS idx_ci_gate_overrides_lookup
    ON ci_gate_overrides (tenant_id, repository_asset_id, commit_sha);

COMMENT ON TABLE ci_gate_overrides IS
    'Break-glass for the CI gate (RFC-051): one commit of one repository passes until expires_at. Created and used under audit.';

INSERT INTO permissions (id, module_id, name, description) VALUES
    ('scans:ci:read', 'scans', 'View CI Runs', 'See CI runs, their verdicts, the CI trust configurations and the gate policies'),
    ('scans:ci:write', 'scans', 'Manage CI Trust and Gate', 'Create, change and delete CI trust configurations and gate policies'),
    ('scans:ci:override', 'scans', 'Override the CI Gate', 'Let one commit pass the CI gate for a limited time (break-glass, audited)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid), -- owner
    ('00000000-0000-0000-0000-000000000002'::uuid)  -- admin
) AS r(role_id)
CROSS JOIN (VALUES ('scans:ci:read'), ('scans:ci:write'), ('scans:ci:override')) AS p(permission_id)
ON CONFLICT DO NOTHING;

-- Members and viewers may read CI runs, as they read scans.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'scans:ci:read'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000003'::uuid), -- member
    ('00000000-0000-0000-0000-000000000004'::uuid)  -- viewer
) AS r(role_id)
WHERE EXISTS (SELECT 1 FROM roles WHERE id = r.role_id)
ON CONFLICT DO NOTHING;

-- Admin-only on custom roles too (pkg/domain/permission/admin_only.go).
CREATE OR REPLACE FUNCTION refuse_admin_only_permission_on_custom_role()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete',
                             'scans:ci:write', 'scans:ci:override')
       AND EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'permission % is reserved for the owner and admin roles and cannot be put on a custom role',
            NEW.permission_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
