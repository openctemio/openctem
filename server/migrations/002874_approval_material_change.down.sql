DELETE FROM finding_decision_reviews WHERE reason = 'material_change_accepted';
ALTER TABLE finding_decision_reviews DROP CONSTRAINT IF EXISTS chk_finding_decision_reviews_reason;
ALTER TABLE finding_decision_reviews ADD CONSTRAINT chk_finding_decision_reviews_reason
    CHECK (reason IN ('taint_source_changed', 'ioc_match', 'material_change_single_person', 'second_look_sample',
                      'acceptance_exceeds_cap')) NOT VALID;
DROP INDEX IF EXISTS idx_finding_status_approvals_standing;
ALTER TABLE finding_status_approvals DROP COLUMN IF EXISTS last_checked_at;
ALTER TABLE finding_status_approvals DROP COLUMN IF EXISTS facts_baseline;
