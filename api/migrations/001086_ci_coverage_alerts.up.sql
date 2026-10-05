-- CI coverage, alerts and stale sources (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md §10.6).
--
--   ci_coverage_expectations  repositories an administrator expects to be
--                             scanned (per capability: sast, sca, secrets,
--                             iac; empty = all four), so "never scanned"
--                             shows as a gap
--   ci_alert_state            one row per (subject, alert kind) while the
--                             condition holds: an alert is sent when the row
--                             is created and again only after it cleared
--                             (de-duplication per pipeline or repository)
--   ci_pipelines.retired_*    an administrator retired the pipeline: its
--                             sole findings were closed as "source retired"
--
-- Four notification event types (sensor category, scans module): a
-- scheduled scan missed, a repository lost its fresh coverage, a default
-- branch fails the gate, a runner below the minimum supported version.
--
-- Live impact: new tables and nullable columns only; four catalog rows.

CREATE TABLE IF NOT EXISTS ci_coverage_expectations (
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    repository_asset_id UUID        NOT NULL,
    capabilities        TEXT[]      NOT NULL DEFAULT '{}',
    created_by          UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, repository_asset_id),
    CONSTRAINT fk_ci_coverage_expectations_asset FOREIGN KEY (tenant_id, repository_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ci_coverage_expectations_caps CHECK (capabilities <@ ARRAY['sast', 'sca', 'secrets', 'iac']::text[])
);

COMMENT ON TABLE ci_coverage_expectations IS
    'Repositories expected to be scanned, per capability (RFC-051 §10.6). Empty capabilities = all.';

CREATE TABLE IF NOT EXISTS ci_alert_state (
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id UUID        NOT NULL,
    kind       VARCHAR(40) NOT NULL,
    fired_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detail     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, subject_id, kind),
    CONSTRAINT chk_ci_alert_state_kind CHECK (kind IN ('schedule_missed', 'coverage_regression', 'gate_failing', 'runner_outdated')),
    CONSTRAINT chk_ci_alert_state_detail CHECK (jsonb_typeof(detail) = 'object')
);

COMMENT ON TABLE ci_alert_state IS
    'CI alerts currently firing, one per subject (pipeline or repository) and kind (RFC-051 §10.6). A row exists while the condition holds; the notification is sent once, when it appears.';

ALTER TABLE ci_pipelines
    ADD COLUMN IF NOT EXISTS retired_at    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retired_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS retire_reason TEXT;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ci_pipelines_retire_reason') THEN
        ALTER TABLE ci_pipelines ADD CONSTRAINT chk_ci_pipelines_retire_reason
            CHECK (retire_reason IS NULL OR char_length(retire_reason) BETWEEN 10 AND 2000);
    END IF;
END $$;

INSERT INTO event_types (id, name, description, category, module_id, default_severity, is_active)
SELECT v.id, v.name, v.description, 'sensor', m.id, v.sev, TRUE
FROM (VALUES
    ('ci.schedule_missed', 'CI scheduled scan missed', 'A CI pipeline with a schedule missed two expected runs', 'high'),
    ('ci.coverage_regression', 'CI coverage lost', 'A repository that had a fresh CI pipeline has none any more', 'high'),
    ('ci.gate_failing', 'CI default branch failing', 'The default branch of a repository fails the CI gate', 'medium'),
    ('ci.runner_outdated', 'CI runner outdated', 'A CI pipeline runs a sensor older than the minimum supported version', 'medium')
) AS v(id, name, description, sev)
LEFT JOIN modules m ON m.id = 'scans'
ON CONFLICT (id) DO NOTHING;
