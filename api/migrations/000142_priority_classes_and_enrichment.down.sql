-- Rollback 000142: Priority Classes + Enrichment
DROP TABLE IF EXISTS priority_class_audit_log;
DROP TABLE IF EXISTS priority_override_rules;

ALTER TABLE sla_policies DROP COLUMN IF EXISTS p0_days;
ALTER TABLE sla_policies DROP COLUMN IF EXISTS p1_days;
ALTER TABLE sla_policies DROP COLUMN IF EXISTS p2_days;
ALTER TABLE sla_policies DROP COLUMN IF EXISTS p3_days;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_priority_class;
ALTER TABLE findings DROP COLUMN IF EXISTS reachable_from_count;
ALTER TABLE findings DROP COLUMN IF EXISTS is_reachable;
ALTER TABLE findings DROP COLUMN IF EXISTS priority_class_overridden_at;
ALTER TABLE findings DROP COLUMN IF EXISTS priority_class_overridden_by;
ALTER TABLE findings DROP COLUMN IF EXISTS priority_class_override;
ALTER TABLE findings DROP COLUMN IF EXISTS priority_class_reason;
ALTER TABLE findings DROP COLUMN IF EXISTS priority_class;
ALTER TABLE findings DROP COLUMN IF EXISTS kev_due_date;
ALTER TABLE findings DROP COLUMN IF EXISTS is_in_kev;
ALTER TABLE findings DROP COLUMN IF EXISTS epss_percentile;
ALTER TABLE findings DROP COLUMN IF EXISTS epss_score;
