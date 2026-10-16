-- Material change of standing decisions
-- (api/docs/rfcs/RFC-111-approval-policy.md §6): an approved accepted risk,
-- or a false positive one person decided, keeps a moving baseline of the
-- finding facts it was last checked against (facts_baseline, starting at the
-- decision facts). The material-change controller compares it with the facts
-- now and ends, flags or revokes the decision; an accepted risk that is
-- flagged rather than ended gets the review reason material_change_accepted.
--
-- last_checked_at is when the controller last looked at the decision, on
-- every attempt including a failed one; the controller takes the least
-- recently checked first, so a decision that keeps failing cannot hold the
-- batch and starve other organizations.
--
-- Live impact: two nullable columns (catalog change); the review reason CHECK
-- is re-added NOT VALID (no scan) and validated by the next migration; a
-- partial index on the few standing approved decisions, built in place
-- (finding_status_approvals is small: approvals are rare).

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS facts_baseline jsonb;

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS last_checked_at timestamptz;

COMMENT ON COLUMN finding_status_approvals.last_checked_at IS
    'When the material-change controller last looked at this decision, successful or not (RFC-111 §6); NULL: never';

COMMENT ON COLUMN finding_status_approvals.facts_baseline IS
    'Finding facts the material-change controller last checked this decision against (RFC-111 §6); NULL until the first check';

CREATE INDEX IF NOT EXISTS idx_finding_status_approvals_standing
    ON finding_status_approvals (tenant_id, finding_id)
    WHERE status = 'approved' AND requested_status IN ('accepted', 'false_positive');

ALTER TABLE finding_decision_reviews DROP CONSTRAINT IF EXISTS chk_finding_decision_reviews_reason;
ALTER TABLE finding_decision_reviews ADD CONSTRAINT chk_finding_decision_reviews_reason
    CHECK (reason IN ('taint_source_changed', 'ioc_match', 'material_change_single_person', 'second_look_sample',
                      'acceptance_exceeds_cap', 'material_change_accepted')) NOT VALID;
