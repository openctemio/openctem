-- Closed findings with no close date (resolved_at) are invisible to MTTR and
-- close-date windows. Where the finding's timeline records the move into its
-- current closed status, the latest such entry is its close date. Rows with
-- no such entry are left as they are (no date is invented). Idempotent and
-- per row: each date comes from the finding's own timeline, in its tenant.
UPDATE findings f
SET resolved_at = t.closed_at
FROM (
    SELECT f2.id, MAX(a.created_at) AS closed_at
    FROM findings f2
    JOIN finding_activities a ON a.tenant_id = f2.tenant_id AND a.finding_id = f2.id
    WHERE f2.status IN ('resolved', 'false_positive', 'accepted', 'duplicate')
      AND f2.resolved_at IS NULL
      AND (a.changes->>'new_status' = f2.status
           OR (a.activity_type = 'resolved' AND f2.status = 'resolved')
           OR (a.activity_type = 'auto_resolved' AND f2.status = 'resolved')
           OR (a.activity_type = 'false_positive_marked' AND f2.status = 'false_positive')
           OR (a.activity_type = 'duplicate_marked' AND f2.status = 'duplicate'))
    GROUP BY f2.id
) t
WHERE f.id = t.id AND f.resolved_at IS NULL;
