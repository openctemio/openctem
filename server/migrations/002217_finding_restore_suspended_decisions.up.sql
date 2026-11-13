-- Before 002173, a changed taint source moved a person's false-positive or
-- accepted decision back to confirmed (resolution decision_suspended) and
-- kept the decision in finding_decision_suspensions. A decision is never
-- reversed automatically any more: restore each such finding to its latest
-- suspended decision, with a timeline entry in its own tenant, and raise the
-- review flag that the same signal raises today. Idempotent: only findings
-- still confirmed with resolution decision_suspended match.

WITH s AS (
    SELECT DISTINCT ON (f.id) f.id, f.tenant_id, s.prior_status, s.prior_resolution
    FROM findings f
    JOIN finding_decision_suspensions s ON s.tenant_id = f.tenant_id AND s.finding_id = f.id
    WHERE f.status = 'confirmed' AND f.resolution = 'decision_suspended'
      AND s.prior_status IN ('false_positive', 'accepted')
    ORDER BY f.id, s.created_at DESC
), restored AS (
    UPDATE findings f
    SET status = s.prior_status,
        resolution = s.prior_resolution,
        resolved_at = NOW(),
        acceptance_expires_at = CASE WHEN s.prior_status = 'accepted' THEN NOW() + INTERVAL '90 days' END,
        updated_at = NOW()
    FROM s
    WHERE f.id = s.id AND f.status = 'confirmed' AND f.resolution = 'decision_suspended'
    RETURNING f.id, f.tenant_id, s.prior_status
)
INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
SELECT r.tenant_id, r.id, 'status_changed', 'system',
       jsonb_build_object('old_status', 'confirmed', 'new_status', r.prior_status, 'reason', 'decision_restored'),
       'system', 'The ' || r.prior_status || ' decision is restored: a changed taint source no longer reverses a decision; it is flagged for review'
FROM restored r;

-- The review flag (a separate statement: the status change above clears open
-- flags of a finding when its row trigger fires at the end of that statement).
INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason, evidence)
SELECT f.tenant_id, f.id, f.status, 'taint_source_changed',
       jsonb_build_object('old_source_hash', s.old_source_hash, 'new_source_hash', s.new_source_hash, 'restored', true)
FROM findings f
JOIN LATERAL (
    SELECT old_source_hash, new_source_hash FROM finding_decision_suspensions s
    WHERE s.tenant_id = f.tenant_id AND s.finding_id = f.id ORDER BY s.created_at DESC LIMIT 1
) s ON TRUE
WHERE EXISTS (SELECT 1 FROM finding_activities a WHERE a.tenant_id = f.tenant_id AND a.finding_id = f.id
              AND a.changes->>'reason' = 'decision_restored')
  AND f.status IN ('false_positive', 'accepted')
ON CONFLICT (tenant_id, finding_id, reason) WHERE cleared_at IS NULL DO NOTHING;

INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
SELECT r.tenant_id, r.finding_id, 'decision_review', 'system', 'system: taint_source_changed',
       jsonb_build_object('decision_status', r.decision_status, 'reason', r.reason, 'evidence', r.evidence),
       'auto', 'The ' || r.decision_status || ' decision may need review (taint_source_changed); it stands until a person decides'
FROM finding_decision_reviews r
WHERE r.cleared_at IS NULL AND r.evidence->>'restored' = 'true'
  AND NOT EXISTS (SELECT 1 FROM finding_activities a WHERE a.tenant_id = r.tenant_id AND a.finding_id = r.finding_id
                  AND a.activity_type = 'decision_review');
