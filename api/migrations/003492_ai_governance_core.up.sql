-- AI governance core (docs/architecture/ai-analysis.md).
--
-- Every AI result is a suggestion with provenance:
--   ai_runs            one row per execution of an AI use case, any executor;
--                      provenance (model, prompt template id and digest, output
--                      schema, bundle digest, fields sent and withheld, usage).
--   ai_suggestions     the typed results of a run; direction (additive, raises
--                      risk, lowers risk) is computed by the platform; state
--                      records apply, approval, dismissal and undo.
--   tenant_ai_use_cases the organization's mode per use case (off, suggest,
--                      auto_apply) and its limits.
--
-- ai_triage_results is copied into ai_runs and ai_suggestions here (a run
-- keeps the id of the triage result it came from, so the built-in executor can
-- write both until ai_triage_results is dropped in a later contract step).
--
-- Live impact: three new tables; one INSERT ... SELECT over ai_triage_results
-- (thousands of rows at most) and one over its completed rows. No lock on an
-- existing table beyond the read, and the finding_activities constraint is
-- re-added NOT VALID (no scan).

CREATE TABLE ai_runs (
    id                     uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id              uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    use_case               varchar(32) NOT NULL,
    kind                   varchar(48) NOT NULL,
    subject_type           varchar(16) NOT NULL,
    subject_id             uuid        NOT NULL,
    executor               varchar(16) NOT NULL DEFAULT 'builtin',
    sensor_id              uuid,
    command_id             uuid,
    status                 varchar(16) NOT NULL DEFAULT 'pending',
    data_class             varchar(16) NOT NULL DEFAULT 'internal',
    fields_sent            text[]      NOT NULL DEFAULT '{}',
    fields_withheld        text[]      NOT NULL DEFAULT '{}',
    bundle_digest          varchar(71),
    grant_digest           varchar(71),
    prompt_template_id     varchar(64),
    prompt_template_digest varchar(71),
    output_schema          varchar(64),
    provider               varchar(50),
    model                  varchar(128),
    model_params           jsonb       NOT NULL DEFAULT '{}',
    steps                  integer     NOT NULL DEFAULT 0,
    tool_calls             integer     NOT NULL DEFAULT 0,
    tokens_in              integer     NOT NULL DEFAULT 0,
    tokens_out             integer     NOT NULL DEFAULT 0,
    cost_micro_usd         bigint      NOT NULL DEFAULT 0,
    duration_ms            integer,
    run_record_ref         text,
    run_record_digest      varchar(71),
    error_code             varchar(64),
    shadow                 boolean     NOT NULL DEFAULT false,
    requested_by           uuid        REFERENCES users(id) ON DELETE SET NULL,
    trigger                varchar(16) NOT NULL DEFAULT 'on_demand',
    started_at             timestamptz,
    completed_at           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_runs PRIMARY KEY (id),
    CONSTRAINT uq_ai_runs_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT chk_ai_runs_use_case CHECK (use_case IN ('triage', 'remediation', 'summary')),
    CONSTRAINT chk_ai_runs_kind CHECK (kind ~ '^[a-z_]{1,32}\.(v[0-9]{1,3}|legacy)$'),
    CONSTRAINT chk_ai_runs_subject_type CHECK (subject_type IN ('finding', 'asset', 'cve', 'attack_path', 'bounty_report')),
    CONSTRAINT chk_ai_runs_executor CHECK (executor IN ('builtin', 'platform_worker', 'tenant_worker')),
    CONSTRAINT chk_ai_runs_worker CHECK ((executor = 'builtin') = (sensor_id IS NULL)),
    CONSTRAINT chk_ai_runs_status CHECK (status IN ('pending', 'running', 'completed', 'incomplete', 'failed', 'refused')),
    CONSTRAINT chk_ai_runs_data_class CHECK (data_class IN ('public', 'internal', 'restricted', 'tenant_only')),
    CONSTRAINT chk_ai_runs_fields CHECK (cardinality(fields_sent) <= 128 AND cardinality(fields_withheld) <= 128),
    CONSTRAINT chk_ai_runs_digests CHECK (
        (bundle_digest IS NULL OR bundle_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (grant_digest IS NULL OR grant_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (prompt_template_digest IS NULL OR prompt_template_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (run_record_digest IS NULL OR run_record_digest ~ '^sha256:[0-9a-f]{64}$')),
    CONSTRAINT chk_ai_runs_model_params CHECK (octet_length(model_params::text) <= 2048),
    CONSTRAINT chk_ai_runs_usage CHECK (steps >= 0 AND tool_calls >= 0 AND tokens_in >= 0 AND tokens_out >= 0
        AND cost_micro_usd >= 0 AND (duration_ms IS NULL OR duration_ms >= 0)),
    CONSTRAINT chk_ai_runs_error_code CHECK (error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,64}$'),
    CONSTRAINT chk_ai_runs_trigger CHECK (trigger IN ('on_demand', 'on_ingest', 'workflow', 'schedule'))
);
CREATE INDEX idx_ai_runs_subject ON ai_runs (tenant_id, subject_type, subject_id, created_at DESC);
CREATE INDEX idx_ai_runs_tenant_created ON ai_runs (tenant_id, created_at DESC);
CREATE INDEX idx_ai_runs_requested_by ON ai_runs (requested_by) WHERE requested_by IS NOT NULL;
COMMENT ON TABLE ai_runs IS
    'One execution of an AI use case (any executor) with its provenance: model, prompt template id and digest, output schema, bundle digest, fields sent and withheld, usage. Tenant-scoped; deleted with the organization.';
COMMENT ON COLUMN ai_runs.error_code IS 'Fixed failure code only; never provider or model text.';

CREATE POLICY ai_runs_tenant_isolation ON ai_runs
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE ai_suggestions (
    id             uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id      uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id         uuid        NOT NULL,
    use_case       varchar(32) NOT NULL,
    subject_type   varchar(16) NOT NULL,
    subject_id     uuid        NOT NULL,
    kind           varchar(32) NOT NULL,
    payload        jsonb       NOT NULL,
    schema_version varchar(64) NOT NULL,
    direction      varchar(16) NOT NULL,
    confidence     real,
    evidence       jsonb       NOT NULL DEFAULT '[]',
    state          varchar(20) NOT NULL DEFAULT 'open',
    review_reasons text[]      NOT NULL DEFAULT '{}',
    previous_value jsonb,
    applied_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    applied_at     timestamptz,
    approval_kind  varchar(16),
    approval_id    uuid,
    undone_by      uuid        REFERENCES users(id) ON DELETE SET NULL,
    undone_at      timestamptz,
    decided_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    decided_at     timestamptz,
    feedback       jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_suggestions PRIMARY KEY (id),
    CONSTRAINT fk_ai_suggestions_run FOREIGN KEY (run_id, tenant_id) REFERENCES ai_runs (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_ai_suggestions_use_case CHECK (use_case IN ('triage', 'remediation', 'summary')),
    CONSTRAINT chk_ai_suggestions_subject_type CHECK (subject_type IN ('finding', 'asset', 'cve', 'attack_path', 'bounty_report')),
    CONSTRAINT chk_ai_suggestions_kind CHECK (kind IN ('verdict', 'severity', 'priority', 'remediation_steps',
        'duplicate_link', 'asset_attribute', 'attack_edge', 'followup_request', 'summary')),
    CONSTRAINT chk_ai_suggestions_payload CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 32768),
    CONSTRAINT chk_ai_suggestions_direction CHECK (direction IN ('additive', 'raises_risk', 'lowers_risk')),
    CONSTRAINT chk_ai_suggestions_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    CONSTRAINT chk_ai_suggestions_evidence CHECK (jsonb_typeof(evidence) = 'array' AND octet_length(evidence::text) <= 16384),
    CONSTRAINT chk_ai_suggestions_state CHECK (state IN ('open', 'applied', 'auto_applied', 'pending_approval',
        'dismissed', 'superseded', 'undone', 'needs_review', 'shadow')),
    CONSTRAINT chk_ai_suggestions_review_reasons CHECK (cardinality(review_reasons) <= 16),
    CONSTRAINT chk_ai_suggestions_previous CHECK (previous_value IS NULL OR octet_length(previous_value::text) <= 4096),
    CONSTRAINT chk_ai_suggestions_approval CHECK ((approval_kind IS NULL) = (approval_id IS NULL)
        AND (approval_kind IS NULL OR approval_kind IN ('status', 'severity'))),
    CONSTRAINT chk_ai_suggestions_feedback CHECK (feedback IS NULL OR octet_length(feedback::text) <= 2048)
);
CREATE INDEX idx_ai_suggestions_subject ON ai_suggestions (tenant_id, subject_type, subject_id, created_at DESC);
CREATE INDEX idx_ai_suggestions_run ON ai_suggestions (tenant_id, run_id);
CREATE INDEX idx_ai_suggestions_decided ON ai_suggestions (tenant_id, use_case, decided_at DESC) WHERE decided_at IS NOT NULL;
CREATE INDEX idx_ai_suggestions_approval ON ai_suggestions (tenant_id, approval_id) WHERE approval_id IS NOT NULL;
CREATE INDEX idx_ai_suggestions_applied_by ON ai_suggestions (applied_by) WHERE applied_by IS NOT NULL;
CREATE INDEX idx_ai_suggestions_undone_by ON ai_suggestions (undone_by) WHERE undone_by IS NOT NULL;
CREATE INDEX idx_ai_suggestions_decided_by ON ai_suggestions (decided_by) WHERE decided_by IS NOT NULL;
COMMENT ON TABLE ai_suggestions IS
    'Typed AI suggestions of a run. direction is computed by the platform from the finding facts, never taken from the model. Risk-lowering suggestions are never applied automatically; they become approval requests. previous_value is read at apply time for undo.';

CREATE POLICY ai_suggestions_tenant_isolation ON ai_suggestions
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE tenant_ai_use_cases (
    tenant_id          uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    use_case           varchar(32)  NOT NULL,
    mode               varchar(16)  NOT NULL DEFAULT 'suggest',
    executor           varchar(16)  NOT NULL DEFAULT 'builtin',
    data_class_ceiling varchar(16)  NOT NULL DEFAULT 'internal',
    min_confidence     numeric(3,2) NOT NULL DEFAULT 0.85,
    triggers           text[]       NOT NULL DEFAULT '{on_demand}',
    budget_share       smallint     NOT NULL DEFAULT 100,
    downgraded_at      timestamptz,
    downgrade_reason   varchar(64),
    updated_by         uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_tenant_ai_use_cases PRIMARY KEY (tenant_id, use_case),
    CONSTRAINT chk_tenant_ai_use_cases_use_case CHECK (use_case IN ('triage', 'remediation', 'summary')),
    CONSTRAINT chk_tenant_ai_use_cases_mode CHECK (mode IN ('off', 'suggest', 'auto_apply')),
    CONSTRAINT chk_tenant_ai_use_cases_executor CHECK (executor IN ('builtin', 'platform_worker', 'tenant_worker')),
    CONSTRAINT chk_tenant_ai_use_cases_class CHECK (data_class_ceiling IN ('public', 'internal', 'restricted', 'tenant_only')),
    CONSTRAINT chk_tenant_ai_use_cases_confidence CHECK (min_confidence >= 0.50 AND min_confidence <= 0.99),
    CONSTRAINT chk_tenant_ai_use_cases_triggers CHECK (triggers <@ ARRAY['on_demand', 'on_ingest', 'workflow', 'schedule']::text[]),
    CONSTRAINT chk_tenant_ai_use_cases_budget CHECK (budget_share BETWEEN 1 AND 100),
    CONSTRAINT chk_tenant_ai_use_cases_downgrade CHECK (downgrade_reason IS NULL OR downgrade_reason ~ '^[a-z0-9_]{1,64}$')
);
CREATE INDEX idx_tenant_ai_use_cases_updated_by ON tenant_ai_use_cases (updated_by) WHERE updated_by IS NOT NULL;
COMMENT ON TABLE tenant_ai_use_cases IS
    'The organization''s policy per AI use case: off, suggest or auto_apply (additive and risk-raising changes only; risk-lowering changes always need approval). A row is written when an administrator changes a use case or the override rate downgrades it; with no row the platform default applies.';

CREATE POLICY tenant_ai_use_cases_tenant_isolation ON tenant_ai_use_cases
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

-- ---------------------------------------------------------------------------
-- Copy ai_triage_results. A run keeps the triage result's id. Of several
-- pending rows for one finding only the newest stays pending (the dedup index
-- below allows one); the others are recorded as failed/superseded.
-- ---------------------------------------------------------------------------
INSERT INTO ai_runs (id, tenant_id, use_case, kind, subject_type, subject_id, executor, status,
                     data_class, prompt_template_id, output_schema, provider, model,
                     tokens_in, tokens_out, error_code, requested_by, trigger,
                     started_at, completed_at, created_at, updated_at)
SELECT r.id, r.tenant_id, 'triage', 'triage.legacy', 'finding', r.finding_id, 'builtin',
       CASE
           WHEN r.status IN ('pending', 'processing')
                AND r.id <> first_value(r.id) OVER (PARTITION BY r.tenant_id, r.finding_id,
                                                    r.status IN ('pending', 'processing')
                                                    ORDER BY r.created_at DESC, r.id DESC)
               THEN 'failed'
           WHEN r.status = 'pending' THEN 'pending'
           WHEN r.status = 'processing' THEN 'running'
           WHEN r.status = 'completed' THEN 'completed'
           ELSE 'failed'
       END,
       'internal', 'triage.legacy', 'openctem.ai.triage/legacy',
       left(r.llm_provider, 50), left(r.llm_model, 128),
       GREATEST(r.prompt_tokens, 0), GREATEST(r.completion_tokens, 0),
       CASE
           WHEN r.status IN ('pending', 'processing')
                AND r.id <> first_value(r.id) OVER (PARTITION BY r.tenant_id, r.finding_id,
                                                    r.status IN ('pending', 'processing')
                                                    ORDER BY r.created_at DESC, r.id DESC)
               THEN 'superseded'
           WHEN r.status = 'failed' AND r.error_message ~ '^[a-z0-9_]{1,64}$' THEN r.error_message
           WHEN r.status = 'failed' THEN 'legacy_failure'
       END,
       r.requested_by,
       CASE r.triage_type WHEN 'auto' THEN 'on_ingest' WHEN 'workflow' THEN 'workflow' ELSE 'on_demand' END,
       r.started_at, r.completed_at, r.created_at, r.updated_at
FROM ai_triage_results r
WHERE EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id)
ON CONFLICT (id) DO NOTHING;

-- One run in flight per organization, use case and subject (shadow runs aside).
CREATE UNIQUE INDEX uq_ai_runs_in_flight ON ai_runs (tenant_id, use_case, subject_id)
    WHERE status IN ('pending', 'running') AND NOT shadow;

-- Suggestions of completed triage runs. Only the newest completed run of a
-- finding has open suggestions; older ones are superseded.
WITH done AS (
    SELECT r.*, f.severity AS finding_severity,
           row_number() OVER (PARTITION BY r.tenant_id, r.finding_id ORDER BY r.completed_at DESC NULLS LAST, r.id DESC) AS rn
    FROM ai_triage_results r
    JOIN ai_runs ar ON ar.id = r.id AND ar.status = 'completed'
    JOIN findings f ON f.id = r.finding_id AND f.tenant_id = r.tenant_id
    WHERE r.status = 'completed'
), sev_rank AS (
    SELECT d.*,
           CASE lower(d.severity_assessment) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                                             WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END AS proposed_rank,
           CASE d.finding_severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                                   WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END AS current_rank
    FROM done d
)
INSERT INTO ai_suggestions (tenant_id, run_id, use_case, subject_type, subject_id, kind, payload, schema_version,
                            direction, confidence, state, created_at, updated_at)
SELECT s.tenant_id, s.id, 'triage', 'finding', s.finding_id, x.kind, x.payload, 'openctem.ai.triage/legacy',
       x.direction, x.confidence, CASE WHEN s.rn = 1 THEN 'open' ELSE 'superseded' END,
       COALESCE(s.completed_at, s.created_at), COALESCE(s.completed_at, s.created_at)
FROM sev_rank s
CROSS JOIN LATERAL (
    SELECT 'remediation_steps'::varchar AS kind,
           jsonb_build_object('steps', s.remediation_steps) AS payload,
           'additive'::varchar AS direction, NULL::real AS confidence
    WHERE jsonb_typeof(s.remediation_steps) = 'array' AND jsonb_array_length(s.remediation_steps) > 0
      AND octet_length(s.remediation_steps::text) <= 30000
    UNION ALL
    SELECT 'summary', jsonb_build_object('text', left(s.analysis_summary, 4000)), 'additive', NULL
    WHERE COALESCE(btrim(s.analysis_summary), '') <> ''
    UNION ALL
    SELECT 'verdict',
           jsonb_build_object('verdict', 'likely_false_positive', 'reason', left(COALESCE(s.false_positive_reason, ''), 2000)),
           'lowers_risk', LEAST(GREATEST(s.false_positive_likelihood, 0), 1)::real
    WHERE s.false_positive_likelihood >= 0.9
    UNION ALL
    SELECT 'severity',
           jsonb_build_object('severity', lower(s.severity_assessment), 'reason', left(COALESCE(s.severity_justification, ''), 2000)),
           CASE WHEN s.proposed_rank > s.current_rank THEN 'raises_risk' ELSE 'lowers_risk' END, NULL
    WHERE s.proposed_rank > 0 AND s.current_rank > 0 AND s.proposed_rank <> s.current_rank
) x;

-- Timeline entries for an applied and an undone AI suggestion. The list is
-- read back from the constraint and written again with the new values.
DO $$
DECLARE
    vals text[];
    added text[] := ARRAY['ai_suggestion_applied', 'ai_suggestion_undone'];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND NOT vals @> added THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM (SELECT DISTINCT unnest(vals || added) AS v) u));
    END IF;
END;
$$;
