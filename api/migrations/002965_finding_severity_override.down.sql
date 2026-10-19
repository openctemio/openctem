-- Removes the analyst severity override. The effective severity stays in
-- findings.severity; the reported severity and the override details are
-- dropped, as are pending and decided severity requests and their timeline
-- entries of the new types.
DROP TRIGGER IF EXISTS trg_findings_severity_source_review ON findings;
DROP FUNCTION IF EXISTS trg_findings_severity_source_review();

DELETE FROM finding_activities WHERE activity_type IN
    ('severity_change_requested', 'severity_change_rejected', 'severity_change_canceled', 'severity_source_changed');

DO $$
DECLARE
    vals text[];
    removed text[] := ARRAY['severity_change_requested', 'severity_change_rejected',
                            'severity_change_canceled', 'severity_source_changed'];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND vals && removed THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(vals) AS v WHERE NOT v = ANY (removed)));
    END IF;
END;
$$;

DELETE FROM approval_signoffs WHERE subject_type = 'severity_request';
ALTER TABLE approval_signoffs DROP CONSTRAINT IF EXISTS chk_approval_signoffs_subject_type;
ALTER TABLE approval_signoffs ADD CONSTRAINT chk_approval_signoffs_subject_type
    CHECK (subject_type IN ('finding_approval', 'approval_batch', 'suppression_rule'));

DROP TABLE IF EXISTS finding_severity_requests;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_severity_overridden_by;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_severity_override;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_source_severity;
ALTER TABLE findings
    DROP COLUMN IF EXISTS severity_overridden_at,
    DROP COLUMN IF EXISTS severity_overridden_by,
    DROP COLUMN IF EXISTS severity_override_reason,
    DROP COLUMN IF EXISTS source_severity;
