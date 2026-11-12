-- Bring the dropped columns back, empty. Lossy: the filters and counts are
-- gone (the tasks hold the work now), every campaign gets an empty filter
-- and zero counts, and paused or validating campaigns stay active. The
-- conversion functions are not recreated (the down of
-- remediation_campaigns_hold_tasks drops them if present).

ALTER TABLE remediation_campaigns DROP CONSTRAINT IF EXISTS chk_remediation_campaigns_status;

ALTER TABLE remediation_campaigns
    ADD COLUMN IF NOT EXISTS finding_filter jsonb DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS finding_count integer DEFAULT 0,
    ADD COLUMN IF NOT EXISTS resolved_count integer DEFAULT 0,
    ADD COLUMN IF NOT EXISTS progress numeric(5,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS risk_score_before numeric(12,2),
    ADD COLUMN IF NOT EXISTS risk_score_after numeric(12,2),
    ADD COLUMN IF NOT EXISTS risk_reduction numeric(12,2);

COMMENT ON TABLE remediation_campaigns IS NULL;
