-- Back to the 000142 shape: column defaults 7/30/60/180, escalation default
-- false. The previous release never reads p0..p3_days or escalation_enabled,
-- so the values written here only restore the old schema; the escalation
-- flags set to true by the up migration cannot be told apart from user
-- choices and are left as they are (the previous release ignores them).

ALTER TABLE sla_policies DROP CONSTRAINT IF EXISTS chk_sla_policies_priority_days;

UPDATE sla_policies SET p0_days = 7 WHERE p0_days IS NULL;
UPDATE sla_policies SET p1_days = 30 WHERE p1_days IS NULL;
UPDATE sla_policies SET p2_days = 60 WHERE p2_days IS NULL;
UPDATE sla_policies SET p3_days = 180 WHERE p3_days IS NULL;

ALTER TABLE sla_policies ALTER COLUMN p0_days SET DEFAULT 7;
ALTER TABLE sla_policies ALTER COLUMN p1_days SET DEFAULT 30;
ALTER TABLE sla_policies ALTER COLUMN p2_days SET DEFAULT 60;
ALTER TABLE sla_policies ALTER COLUMN p3_days SET DEFAULT 180;

ALTER TABLE sla_policies ALTER COLUMN escalation_enabled SET DEFAULT FALSE;

COMMENT ON COLUMN sla_policies.p0_days IS NULL;
COMMENT ON COLUMN sla_policies.p1_days IS NULL;
COMMENT ON COLUMN sla_policies.p2_days IS NULL;
COMMENT ON COLUMN sla_policies.p3_days IS NULL;
COMMENT ON COLUMN sla_policies.escalation_enabled IS NULL;
