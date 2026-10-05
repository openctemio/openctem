-- CI pipelines: the logical identity of a CI scanner (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
-- "Pipelines in the fleet").
--
-- A pipeline is one workflow file of one repository, keyed by ids the CI
-- provider signs into the job's OIDC token and that survive renames:
--
--   GitHub  repository_id + the workflow_ref path (".github/workflows/scan.yml")
--   GitLab  project_id    + the ci_config_ref_uri path (".gitlab-ci.yml")
--
-- The branch, job name and tools are attributes of a run, never part of the
-- key, so branches cannot multiply pipelines. A pipeline is created at a
-- verified token exchange that a trust configuration admitted, up to a cap
-- per tenant. It is not a sensor: no key, no heartbeat, no zone, never
-- dispatched. It is listed in the fleet as a sensor in runner mode.
--
-- Live impact: one new table, five nullable/defaulted columns on ci_runs,
-- and a backfill of one pipeline per (repository, workflow file) of the runs
-- already recorded. Runs recorded before this migration carry no repository
-- id, so their pipelines get the placeholder key "legacy:<asset id>"; the
-- next verified run of the same repository and workflow file adopts the row
-- and writes the real id.

CREATE TABLE IF NOT EXISTS ci_pipelines (
    id                         UUID          PRIMARY KEY,
    tenant_id                  UUID          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider                   VARCHAR(20)   NOT NULL,
    issuer                     VARCHAR(500)  NOT NULL,
    external_repo_id           VARCHAR(64)   NOT NULL,
    workflow_path              VARCHAR(500)  NOT NULL,
    repository_asset_id        UUID          NOT NULL,
    trust_config_id            UUID          REFERENCES ci_trust_configs(id) ON DELETE SET NULL,
    repository_name            VARCHAR(500)  NOT NULL DEFAULT '',
    workflow_name              VARCHAR(255)  NOT NULL DEFAULT '',
    template_ref               VARCHAR(500)  NOT NULL DEFAULT '',
    template_sha               VARCHAR(64)   NOT NULL DEFAULT '',
    default_branch             VARCHAR(255)  NOT NULL DEFAULT '',
    first_run_at               TIMESTAMPTZ,
    last_run_at                TIMESTAMPTZ,
    last_run_id                UUID,
    last_run_status            VARCHAR(20)   NOT NULL DEFAULT '',
    last_fork_run_at           TIMESTAMPTZ,
    runs_count                 INT           NOT NULL DEFAULT 0,
    last_default_run_at        TIMESTAMPTZ,
    last_default_verdict       VARCHAR(10),
    last_default_verdict_at    TIMESTAMPTZ,
    last_pr_verdict            VARCHAR(10),
    last_pr_verdict_at         TIMESTAMPTZ,
    last_scan_failures         INT,
    sensor_version             VARCHAR(64)   NOT NULL DEFAULT '',
    tools                      JSONB         NOT NULL DEFAULT '[]'::jsonb,
    median_interval_seconds    INT,
    schedule_interval_seconds  INT,
    revoked_at                 TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ci_pipelines_asset FOREIGN KEY (tenant_id, repository_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ci_pipelines_provider CHECK (provider IN ('github', 'gitlab')),
    CONSTRAINT chk_ci_pipelines_tools CHECK (jsonb_typeof(tools) = 'array'),
    CONSTRAINT chk_ci_pipelines_verdicts CHECK (
        (last_default_verdict IS NULL OR last_default_verdict IN ('pass', 'fail'))
        AND (last_pr_verdict IS NULL OR last_pr_verdict IN ('pass', 'fail'))),
    CONSTRAINT uq_ci_pipelines_identity UNIQUE (tenant_id, provider, issuer, external_repo_id, workflow_path),
    CONSTRAINT uq_ci_pipelines_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ci_pipelines_tenant_asset
    ON ci_pipelines (tenant_id, repository_asset_id);
CREATE INDEX IF NOT EXISTS idx_ci_pipelines_trust
    ON ci_pipelines (trust_config_id) WHERE trust_config_id IS NOT NULL;

COMMENT ON TABLE ci_pipelines IS
    'CI pipelines (RFC-051): one workflow file of one repository, keyed by the provider''s immutable repository id and the workflow path from verified OIDC claims. Not a sensor: never dispatched, holds no credential.';

ALTER TABLE ci_runs
    ADD COLUMN IF NOT EXISTS pipeline_id    UUID,
    ADD COLUMN IF NOT EXISTS sensor_version VARCHAR(64)  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS scan_failures  INT,
    ADD COLUMN IF NOT EXISTS tools          JSONB        NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS template_ref   VARCHAR(500) NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_ci_runs_pipeline') THEN
        ALTER TABLE ci_runs ADD CONSTRAINT fk_ci_runs_pipeline FOREIGN KEY (tenant_id, pipeline_id)
            REFERENCES ci_pipelines(tenant_id, id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ci_runs_tools') THEN
        ALTER TABLE ci_runs ADD CONSTRAINT chk_ci_runs_tools CHECK (jsonb_typeof(tools) = 'array');
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ci_runs_tenant_pipeline
    ON ci_runs (tenant_id, pipeline_id, created_at DESC) WHERE pipeline_id IS NOT NULL;

-- Backfill: one pipeline per (tenant, provider, issuer, repository asset,
-- workflow path) of the existing runs. The path is the workflow claim
-- without its "@ref" and without the repository prefix (GitHub
-- "owner/name/.github/workflows/x.yml", GitLab "host/group/project//x.yml").
WITH runs AS (
    SELECT r.id, r.tenant_id, r.provider, r.issuer, r.repository_asset_id, r.repository, r.trust_config_id,
           r.default_branch, r.created_at,
           COALESCE(NULLIF(CASE r.provider
               WHEN 'gitlab' THEN COALESCE(substring(regexp_replace(regexp_replace(r.workflow, '@refs/.*$', ''), '@[^@]*$', '') FROM '//(.+)$'), '')
               ELSE regexp_replace(regexp_replace(regexp_replace(r.workflow, '@refs/.*$', ''), '@[^@]*$', ''), '^[^/]+/[^/]+/', '')
           END, ''), CASE r.provider WHEN 'gitlab' THEN '.gitlab-ci.yml' ELSE 'unknown' END) AS workflow_path
    FROM ci_runs r
    WHERE r.pipeline_id IS NULL
), keyed AS (
    SELECT DISTINCT ON (tenant_id, provider, issuer, repository_asset_id, workflow_path)
           tenant_id, provider, issuer, repository_asset_id, workflow_path, repository, trust_config_id, default_branch
    FROM runs
    ORDER BY tenant_id, provider, issuer, repository_asset_id, workflow_path, created_at DESC
)
INSERT INTO ci_pipelines (id, tenant_id, provider, issuer, external_repo_id, workflow_path, repository_asset_id,
                          trust_config_id, repository_name, default_branch)
SELECT gen_random_uuid(), tenant_id, provider, issuer, 'legacy:' || repository_asset_id::text,
       left(workflow_path, 500), repository_asset_id, trust_config_id, repository, default_branch
FROM keyed
ON CONFLICT (tenant_id, provider, issuer, external_repo_id, workflow_path) DO NOTHING;

UPDATE ci_runs r SET pipeline_id = p.id
FROM ci_pipelines p
WHERE r.pipeline_id IS NULL
  AND p.tenant_id = r.tenant_id AND p.provider = r.provider AND p.issuer = r.issuer
  AND p.external_repo_id = 'legacy:' || r.repository_asset_id::text
  AND p.workflow_path = left(COALESCE(NULLIF(CASE r.provider
          WHEN 'gitlab' THEN COALESCE(substring(regexp_replace(regexp_replace(r.workflow, '@refs/.*$', ''), '@[^@]*$', '') FROM '//(.+)$'), '')
          ELSE regexp_replace(regexp_replace(regexp_replace(r.workflow, '@refs/.*$', ''), '@[^@]*$', ''), '^[^/]+/[^/]+/', '')
      END, ''), CASE r.provider WHEN 'gitlab' THEN '.gitlab-ci.yml' ELSE 'unknown' END), 500);

-- The backfilled pipelines' run summary (the application keeps it current
-- from here on; see CIRunRepository.RefreshPipeline).
UPDATE ci_pipelines p SET
    first_run_at = s.first_run_at,
    last_run_at = s.last_run_at,
    runs_count = s.runs_count,
    last_default_verdict = s.last_default_verdict,
    last_default_verdict_at = s.last_default_verdict_at,
    last_default_run_at = s.last_default_run_at
FROM (
    SELECT r.pipeline_id,
           min(r.created_at) FILTER (WHERE NOT r.fork) AS first_run_at,
           max(r.created_at) FILTER (WHERE NOT r.fork) AS last_run_at,
           count(*) FILTER (WHERE NOT r.fork)::int AS runs_count,
           max(r.created_at) FILTER (WHERE NOT r.fork AND r.is_default_branch) AS last_default_run_at,
           (array_agg(r.verdict ORDER BY r.evaluated_at DESC)
               FILTER (WHERE NOT r.fork AND r.is_default_branch AND r.verdict IS NOT NULL))[1] AS last_default_verdict,
           max(r.evaluated_at) FILTER (WHERE NOT r.fork AND r.is_default_branch AND r.verdict IS NOT NULL) AS last_default_verdict_at
    FROM ci_runs r
    WHERE r.pipeline_id IS NOT NULL
    GROUP BY r.pipeline_id
) s
WHERE p.id = s.pipeline_id AND p.external_repo_id LIKE 'legacy:%';
