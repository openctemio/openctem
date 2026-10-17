-- An accepted risk always ends. Accepted findings that still have no end
-- (accepted before the end was recorded, with no approval or rule end to take
-- it from) get the policy default, 90 days from now, with a timeline note in
-- the finding's own tenant. Idempotent: only rows without an end match.
WITH due AS (
    SELECT id FROM findings
    WHERE status = 'accepted' AND acceptance_expires_at IS NULL
    FOR UPDATE
), ended AS (
    UPDATE findings f
    SET acceptance_expires_at = NOW() + INTERVAL '90 days', updated_at = NOW()
    FROM due
    WHERE f.id = due.id
    RETURNING f.id, f.tenant_id, f.acceptance_expires_at
)
INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
SELECT e.tenant_id, e.id, 'metadata_updated', 'system',
       jsonb_build_object('field', 'acceptance_expires_at',
                          'acceptance_expires_at', to_char(e.acceptance_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                          'reason', 'acceptance_end_default'),
       'system', 'The risk acceptance had no end: it ends after the 90-day default'
FROM ended e;
