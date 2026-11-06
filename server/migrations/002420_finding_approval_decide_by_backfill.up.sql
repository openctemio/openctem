-- Pending requests made before decide_by existed get the default window
-- (14 days) from their creation. A request older than that expires at the
-- next run of the approval expiration job, with a timeline entry and an audit
-- row, as any other overdue request.
--
-- Live impact: the table is small (no finding request exists on live on
-- 2026-10-15); only pending rows without a decide-by time are touched.

UPDATE finding_status_approvals
SET decide_by = created_at + INTERVAL '14 days'
WHERE status = 'pending' AND decide_by IS NULL;
