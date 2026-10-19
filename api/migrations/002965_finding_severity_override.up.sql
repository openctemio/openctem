-- Analyst severity override of a finding
-- (api/docs/architecture/finding-severity-override.md).
--
-- findings.severity stays the EFFECTIVE severity, so every reader (filters,
-- dashboards, the priority classifier, SLA windows, approvals) is unchanged.
-- Next to it:
--   source_severity           what the tools reported, kept while an override
--                             stands; NULL means "equal to severity" (no
--                             override was ever made, or it was restored)
--   severity_override_reason  why the analyst set the severity
--   severity_overridden_by    who (users; SET NULL when the account is erased)
--   severity_overridden_at    when; NULL = no override stands
-- Ingest and re-sightings write source_severity only while an override
-- stands; a change of it raises a severity_source_changed timeline entry for
-- review (trigger below) instead of reverting the analyst.
--
-- A downgrade of the effective severity that the organization's approval
-- policy does not let one person decide waits in finding_severity_requests
-- (one pending request per finding); each sign-off is a row in
-- approval_signoffs (subject_type severity_request).
--
-- Live impact: four nullable columns on findings without a default (catalog
-- change, no rewrite); existing findings keep their severity as the effective
-- one with no override. CHECK and FOREIGN KEY constraints on findings and the
-- finding_activities CHECK are added NOT VALID (no scan under the lock);
-- finding_severity_override_validate validates them. The new table is empty.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS source_severity varchar(20),
    ADD COLUMN IF NOT EXISTS severity_override_reason text,
    ADD COLUMN IF NOT EXISTS severity_overridden_by uuid,
    ADD COLUMN IF NOT EXISTS severity_overridden_at timestamptz;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_source_severity;
ALTER TABLE findings ADD CONSTRAINT chk_findings_source_severity
    CHECK (source_severity IS NULL OR source_severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')) NOT VALID;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_severity_override;
ALTER TABLE findings ADD CONSTRAINT chk_findings_severity_override
    CHECK (severity_overridden_at IS NULL
           OR (source_severity IS NOT NULL AND severity_override_reason IS NOT NULL AND btrim(severity_override_reason) <> '')) NOT VALID;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_severity_overridden_by;
ALTER TABLE findings ADD CONSTRAINT fk_findings_severity_overridden_by
    FOREIGN KEY (severity_overridden_by) REFERENCES users (id) ON DELETE SET NULL NOT VALID;

COMMENT ON COLUMN findings.source_severity IS
    'Severity the tools reported, kept while an analyst override stands; NULL = equal to severity';
COMMENT ON COLUMN findings.severity_override_reason IS 'Why the analyst set the effective severity';
COMMENT ON COLUMN findings.severity_overridden_by IS 'Who set the analyst severity override';
COMMENT ON COLUMN findings.severity_overridden_at IS 'When the analyst severity override was set; NULL = no override';

CREATE TABLE IF NOT EXISTS finding_severity_requests (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id          uuid        NOT NULL,
    finding_id         uuid        NOT NULL,
    requested_severity varchar(20) NOT NULL,
    previous_severity  varchar(20) NOT NULL,
    restore            boolean     NOT NULL DEFAULT false,
    reason             text        NOT NULL,
    requested_by       uuid,
    status             varchar(16) NOT NULL DEFAULT 'pending',
    tier               varchar(16) NOT NULL,
    required_approvals smallint    NOT NULL DEFAULT 1,
    decide_by          timestamptz NOT NULL,
    decided_by         uuid,
    decided_at         timestamptz,
    decision_note      text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_finding_severity_requests PRIMARY KEY (id),
    CONSTRAINT fk_finding_severity_requests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_severity_requests_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_severity_requests_requested_by FOREIGN KEY (requested_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_finding_severity_requests_decided_by FOREIGN KEY (decided_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_finding_severity_requests_severity
        CHECK (requested_severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')
               AND previous_severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')),
    CONSTRAINT chk_finding_severity_requests_status
        CHECK (status IN ('pending', 'approved', 'rejected', 'canceled', 'expired')),
    CONSTRAINT chk_finding_severity_requests_tier CHECK (tier IN ('single', 'peer', 'security', 'dual')),
    CONSTRAINT chk_finding_severity_requests_required CHECK (required_approvals BETWEEN 1 AND 3),
    CONSTRAINT chk_finding_severity_requests_reason CHECK (btrim(reason) <> '' AND char_length(reason) <= 1000)
);

COMMENT ON TABLE finding_severity_requests IS
    'Severity downgrades waiting for the approval the organization''s policy asks for; sign-offs in approval_signoffs';

CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_severity_requests_pending
    ON finding_severity_requests (tenant_id, finding_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_finding_severity_requests_finding
    ON finding_severity_requests (tenant_id, finding_id, created_at DESC);

-- approval_signoffs is small (one row per approval given): re-adding the
-- CHECK validates it in place.
ALTER TABLE approval_signoffs DROP CONSTRAINT IF EXISTS chk_approval_signoffs_subject_type;
ALTER TABLE approval_signoffs ADD CONSTRAINT chk_approval_signoffs_subject_type
    CHECK (subject_type IN ('finding_approval', 'approval_batch', 'suppression_rule', 'severity_request'));

-- Timeline entry types: a severity change waiting for approval, its
-- rejection and withdrawal, and a reported severity that changed under an
-- override. The list is read back from the constraint and written again with
-- the new values, whatever other migrations added before this one ran.
DO $$
DECLARE
    vals text[];
    added text[] := ARRAY['severity_change_requested', 'severity_change_rejected',
                          'severity_change_canceled', 'severity_source_changed'];
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

-- Review signal: the reported severity changed while an analyst's override
-- stands. The override is kept; a timeline entry asks a person to look at it.
-- Covers every writer of source_severity (re-sighting, ingest upsert, KEV
-- escalation, license verdicts, correlation).
CREATE OR REPLACE FUNCTION trg_findings_severity_source_review() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
    VALUES (NEW.tenant_id, NEW.id, 'severity_source_changed', 'system', 'system: severity review',
            jsonb_build_object('old_source_severity', OLD.source_severity, 'new_source_severity', NEW.source_severity,
                               'severity', NEW.severity, 'review', true),
            'auto',
            'The reported severity changed from ' || COALESCE(OLD.source_severity, '') || ' to ' || COALESCE(NEW.source_severity, '')
                || ' while an analyst override of ' || NEW.severity || ' stands; review the override');
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION trg_findings_severity_source_review() IS
    'Row trigger: records a severity_source_changed timeline entry when the reported severity of a finding with an analyst override changes';

DROP TRIGGER IF EXISTS trg_findings_severity_source_review ON findings;
CREATE TRIGGER trg_findings_severity_source_review
    AFTER UPDATE OF source_severity ON findings
    FOR EACH ROW
    WHEN (OLD.severity_overridden_at IS NOT NULL AND NEW.severity_overridden_at IS NOT NULL
          AND OLD.source_severity IS DISTINCT FROM NEW.source_severity)
    EXECUTE FUNCTION trg_findings_severity_source_review();
