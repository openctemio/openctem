-- Risk acceptance is capped by priority (see
-- pkg/domain/vulnerability/evidence_matrix.go): P0 or KEV 30 days, P1 90,
-- P2 180, P3 (and unclassified) 365. New requests are held to it by the API.
-- An acceptance that already runs longer is never shortened silently: it is
-- flagged for review (finding_decision_reviews, reason
-- acceptance_exceeds_cap) with a timeline entry, and a person with the
-- approve permission decides. The count is printed (NOTICE) when this runs.

CREATE OR REPLACE FUNCTION finding_max_acceptance_days(p_priority_class text, p_is_kev boolean)
RETURNS integer
LANGUAGE sql
IMMUTABLE PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN p_priority_class = 'P0' OR COALESCE(p_is_kev, false) THEN 30
        WHEN p_priority_class = 'P1' THEN 90
        WHEN p_priority_class = 'P2' THEN 180
        ELSE 365
    END
$$;

COMMENT ON FUNCTION finding_max_acceptance_days(text, boolean) IS
    'Longest risk acceptance in days by priority (vulnerability.MaxAcceptanceFor; a test pins them)';

-- Widening the reason CHECK (validated in acceptance_cap_review_validate).
ALTER TABLE finding_decision_reviews DROP CONSTRAINT chk_finding_decision_reviews_reason;
ALTER TABLE finding_decision_reviews ADD CONSTRAINT chk_finding_decision_reviews_reason
    CHECK (reason IN ('taint_source_changed', 'ioc_match', 'acceptance_exceeds_cap')) NOT VALID;

DO $$
DECLARE
    flagged integer;
BEGIN
    WITH over_cap AS (
        SELECT f.tenant_id, f.id, f.priority_class, f.is_in_kev, f.acceptance_expires_at,
               COALESCE(f.resolved_at, f.updated_at) AS accepted_at,
               finding_max_acceptance_days(f.priority_class, f.is_in_kev) AS max_days
        FROM findings f
        WHERE f.status = 'accepted'
          AND f.acceptance_expires_at IS NOT NULL
          AND f.acceptance_expires_at > COALESCE(f.resolved_at, f.updated_at)
              + make_interval(days => finding_max_acceptance_days(f.priority_class, f.is_in_kev))
    ), flags AS (
        INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason, evidence)
        SELECT o.tenant_id, o.id, 'accepted', 'acceptance_exceeds_cap',
               jsonb_build_object('acceptance_expires_at', o.acceptance_expires_at, 'accepted_at', o.accepted_at,
                                  'max_days', o.max_days, 'priority_class', o.priority_class, 'is_in_kev', o.is_in_kev)
        FROM over_cap o
        ON CONFLICT (tenant_id, finding_id, reason) WHERE cleared_at IS NULL DO NOTHING
        RETURNING tenant_id, finding_id, evidence
    ), timeline AS (
        INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
        SELECT fl.tenant_id, fl.finding_id, 'decision_review', 'system', 'system: acceptance_exceeds_cap',
               jsonb_build_object('decision_status', 'accepted', 'reason', 'acceptance_exceeds_cap', 'evidence', fl.evidence),
               'auto',
               'The accepted risk runs longer than its priority allows now; it stands until a person decides'
        FROM flags fl
        RETURNING 1
    )
    SELECT count(*) INTO flagged FROM timeline;
    RAISE NOTICE 'acceptance_cap_review: % accepted finding(s) flagged for review (acceptance longer than the cap of their priority)', flagged;
END
$$;
