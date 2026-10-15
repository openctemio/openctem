-- One pending request per finding (the unique index is the next migration).
-- Before it, a finding could hold several pending requests from people. The
-- newest pending request of each finding is kept; every older one is
-- cancelled with a timeline entry on its finding, so nothing is decided
-- twice. The count is written as a NOTICE (the dry run of this migration is
-- the SELECT in the DO block).
--
-- Live impact: none expected (no finding request exists on live on
-- 2026-10-15); the table is small.

DO $$
DECLARE
    n integer;
BEGIN
    SELECT COUNT(*) INTO n FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY tenant_id, finding_id ORDER BY created_at DESC, id DESC) AS rn
        FROM finding_status_approvals WHERE status = 'pending'
    ) d WHERE d.rn > 1;
    RAISE NOTICE 'finding_status_approvals: cancelling % duplicate pending request(s)', n;
END $$;

WITH dup AS (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY tenant_id, finding_id ORDER BY created_at DESC, id DESC) AS rn
        FROM finding_status_approvals WHERE status = 'pending'
    ) d WHERE d.rn > 1
), cancelled AS (
    UPDATE finding_status_approvals a SET status = 'canceled', version = a.version + 1
    FROM dup WHERE a.id = dup.id
    RETURNING a.id, a.tenant_id, a.finding_id, a.requested_status
)
INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
SELECT c.tenant_id, c.finding_id, 'approval_canceled', 'system', 'system: one pending request per finding',
       jsonb_build_object('approval_id', c.id, 'approval_status', 'canceled',
                          'requested_status', c.requested_status, 'reason', 'superseded_by_newer_request'),
       'auto', 'A newer pending request exists for this finding; this one was cancelled'
FROM cancelled c;
