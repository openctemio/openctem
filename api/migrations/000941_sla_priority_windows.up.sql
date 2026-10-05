-- SLA policies: make the P0..P3 windows real, and keep escalation on.
--
-- Migration 000142 added sla_policies.p0_days..p3_days with column defaults
-- 7/30/60/180, but no code ever read or wrote them: deadlines always used the
-- hardcoded DefaultPriorityDays (P0=2, P1=5, P2=15, P3=30). From this release
-- the repository reads and writes the columns, and NULL means "inherit the
-- default for that class". Every value stored today is the 000142 column
-- default, never a choice anyone made, so reading it as is would silently
-- stretch every P0 deadline from 2 to 7 days. The values are therefore reset
-- to NULL (= keep today's effective 2/5/15/30) and the column defaults dropped.
--
-- escalation_enabled was stored but ignored: approaching/breached
-- notifications went out for every finding. From this release the escalation
-- controller honours it per policy, so every existing policy is set to true to
-- keep what tenants get today, and new rows default to true.
--
-- Safe on live data: sla_policies holds a handful of rows per tenant; the
-- updates are a single short statement each. During a rolling deploy an old
-- pod inserts policies without p0..p3 (NULL = default, which is what it used)
-- and never reads the columns.

ALTER TABLE sla_policies ALTER COLUMN p0_days DROP DEFAULT;
ALTER TABLE sla_policies ALTER COLUMN p1_days DROP DEFAULT;
ALTER TABLE sla_policies ALTER COLUMN p2_days DROP DEFAULT;
ALTER TABLE sla_policies ALTER COLUMN p3_days DROP DEFAULT;

UPDATE sla_policies
   SET p0_days = NULL, p1_days = NULL, p2_days = NULL, p3_days = NULL
 WHERE p0_days IS NOT NULL OR p1_days IS NOT NULL OR p2_days IS NOT NULL OR p3_days IS NOT NULL;

ALTER TABLE sla_policies ADD CONSTRAINT chk_sla_policies_priority_days CHECK (
    (p0_days IS NULL OR p0_days BETWEEN 1 AND 365) AND
    (p1_days IS NULL OR p1_days BETWEEN 1 AND 365) AND
    (p2_days IS NULL OR p2_days BETWEEN 1 AND 365) AND
    (p3_days IS NULL OR p3_days BETWEEN 1 AND 365)
);

UPDATE sla_policies SET escalation_enabled = TRUE WHERE escalation_enabled = FALSE;
ALTER TABLE sla_policies ALTER COLUMN escalation_enabled SET DEFAULT TRUE;

COMMENT ON COLUMN sla_policies.p0_days IS 'Remediation window (days) for priority class P0; NULL = platform default';
COMMENT ON COLUMN sla_policies.p1_days IS 'Remediation window (days) for priority class P1; NULL = platform default';
COMMENT ON COLUMN sla_policies.p2_days IS 'Remediation window (days) for priority class P2; NULL = platform default';
COMMENT ON COLUMN sla_policies.p3_days IS 'Remediation window (days) for priority class P3; NULL = platform default';
COMMENT ON COLUMN sla_policies.escalation_enabled IS 'Send approaching/breached deadline notifications for findings governed by this policy';
