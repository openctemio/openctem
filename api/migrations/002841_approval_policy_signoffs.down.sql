DROP TABLE IF EXISTS approval_signoffs;
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_required;
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_tier;
ALTER TABLE finding_status_approvals
    DROP COLUMN IF EXISTS decision_facts,
    DROP COLUMN IF EXISTS policy_eval,
    DROP COLUMN IF EXISTS required_approvals,
    DROP COLUMN IF EXISTS risk_class,
    DROP COLUMN IF EXISTS tier;
