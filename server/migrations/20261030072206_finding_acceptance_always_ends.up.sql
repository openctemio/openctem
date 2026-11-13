-- An accepted risk always ends (docs/architecture/suppression-rules.md,
-- "Every rule ends"). Every writer sets findings.acceptance_expires_at, but one
-- path sets it in a separate, best-effort step after the status (a finding
-- an accepted-risk suppression rule matches at ingest), and the CI gate read
-- a missing end as "never ends". This makes the end a database invariant: an
-- accepted row written without an end gets the default acceptance length
-- (90 days), capped by the finding's priority (finding_max_acceptance_days),
-- with a timeline note. A row that has an end keeps it; a later write that
-- sets the end (the rule's expiry, an approval's end) replaces the default.

CREATE OR REPLACE FUNCTION default_finding_acceptance_end() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.acceptance_expires_at := NOW() + make_interval(days => LEAST(90,
        finding_max_acceptance_days(NEW.priority_class::text, NEW.is_in_kev)));
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION default_finding_acceptance_end() IS
    'Gives an accepted finding written without an end the default acceptance length, capped by its priority';

DROP TRIGGER IF EXISTS trg_findings_default_acceptance_end ON findings;
CREATE TRIGGER trg_findings_default_acceptance_end
    BEFORE INSERT OR UPDATE ON findings
    FOR EACH ROW
    WHEN (NEW.status::text = 'accepted' AND NEW.acceptance_expires_at IS NULL)
    EXECUTE FUNCTION default_finding_acceptance_end();

-- Accepted findings that still have no end take it now, with a timeline note
-- in the finding's own tenant. Idempotent: only rows without an end match.
WITH due AS (
    SELECT id FROM findings
    WHERE status = 'accepted' AND acceptance_expires_at IS NULL
    FOR UPDATE
), ended AS (
    UPDATE findings f
    SET acceptance_expires_at = NOW() + make_interval(days => LEAST(90,
            finding_max_acceptance_days(f.priority_class::text, f.is_in_kev))),
        updated_at = NOW()
    FROM due
    WHERE f.id = due.id
    RETURNING f.id, f.tenant_id, f.acceptance_expires_at
)
INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
SELECT e.tenant_id, e.id, 'metadata_updated', 'system',
       jsonb_build_object('field', 'acceptance_expires_at',
                          'acceptance_expires_at', to_char(e.acceptance_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                          'reason', 'acceptance_end_default'),
       'system', 'The risk acceptance had no end: it ends after the default length'
FROM ended e;
