-- Applying an AI worker's result (docs/architecture/ai-analysis.md, "Applying
-- a worker's result"; docs/architecture/ai-autonomy.md).
--
-- 1. ai_runs gains what applying a result later needs and what it records:
--    subject_row_version  the finding's row version when the run built its
--                         bundle: a change by a person after that turns the
--                         AI agent's changes into comments (a person wins);
--    outcome              what the run did to its subject in one word
--                         (applied, proposed, no_change, abstained);
--    action_log           each suggestion and what became of it
--                         (kind, outcome, reason codes only, never text);
--    model_family         the model family a worker reported.
-- 2. tenant_ai_settings.autonomy: the organization's switch and limits on
--    changes an AI agent makes without a person (pause, per hour, per day).
--    NULL reads as the defaults.
-- 3. ai_auto_change_counts: per organization and clock hour, how many such
--    changes were made; the limits are checked against it under a lock.
--
-- Live impact: no data changes. New nullable columns without defaults and a
-- new table: catalog changes only, no rewrite, no long lock. The CHECKs are
-- added NOT VALID then validated (every existing row is NULL, so they hold).

ALTER TABLE ai_runs
    ADD COLUMN subject_row_version bigint,
    ADD COLUMN outcome varchar(16),
    ADD COLUMN action_log jsonb,
    ADD COLUMN model_family varchar(64);

ALTER TABLE ai_runs ADD CONSTRAINT chk_ai_runs_outcome
    CHECK (outcome IS NULL OR outcome IN ('applied', 'proposed', 'no_change', 'abstained')) NOT VALID;
ALTER TABLE ai_runs VALIDATE CONSTRAINT chk_ai_runs_outcome;
ALTER TABLE ai_runs ADD CONSTRAINT chk_ai_runs_action_log
    CHECK (action_log IS NULL OR (jsonb_typeof(action_log) = 'array' AND jsonb_array_length(action_log) <= 32)) NOT VALID;
ALTER TABLE ai_runs VALIDATE CONSTRAINT chk_ai_runs_action_log;
ALTER TABLE ai_runs ADD CONSTRAINT chk_ai_runs_model_family
    CHECK (model_family IS NULL OR model_family ~ '^[a-z0-9][a-z0-9._-]{0,63}$') NOT VALID;
ALTER TABLE ai_runs VALIDATE CONSTRAINT chk_ai_runs_model_family;

COMMENT ON COLUMN ai_runs.subject_row_version IS
    'Row version of the finding when the run built its bundle; a later change by someone else turns the run''s changes into comments.';
COMMENT ON COLUMN ai_runs.outcome IS
    'What the run did to its subject: applied (changed it), proposed (a suggestion or request waits for a person), no_change, abstained.';
COMMENT ON COLUMN ai_runs.action_log IS
    'Each suggestion of the run and what became of it: kind, outcome and reason codes only (never model text).';
COMMENT ON COLUMN ai_runs.model_family IS
    'Model family the AI worker reported for the run (lower case), used to tell independent checks apart.';

ALTER TABLE tenant_ai_settings ADD COLUMN autonomy jsonb;
COMMENT ON COLUMN tenant_ai_settings.autonomy IS
    'Switch and limits on changes AI agents make without a person: {"version":1,"paused":bool,"per_hour":int|null,"per_day":int|null,...}; NULL reads as the defaults, a null limit is unlimited.';

CREATE TABLE ai_auto_change_counts (
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hour_start timestamptz NOT NULL,
    changes    integer     NOT NULL DEFAULT 0,
    CONSTRAINT pk_ai_auto_change_counts PRIMARY KEY (tenant_id, hour_start),
    CONSTRAINT chk_ai_auto_change_counts_changes CHECK (changes >= 0)
);
COMMENT ON TABLE ai_auto_change_counts IS
    'Changes AI agents made without a person, per organization and clock hour (UTC); the organization''s limits are checked against it.';

CREATE POLICY ai_auto_change_counts_tenant_isolation ON ai_auto_change_counts
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
