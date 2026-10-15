ALTER TABLE remediation_campaigns DROP CONSTRAINT IF EXISTS chk_remediation_campaigns_priority;
DROP INDEX IF EXISTS idx_remediation_campaigns_reconcile;
-- The cleared count values are not restored (they were not risk values).
ALTER TABLE remediation_campaigns
    ALTER COLUMN risk_score_before TYPE numeric(5,2),
    ALTER COLUMN risk_score_after TYPE numeric(5,2),
    ALTER COLUMN risk_reduction TYPE numeric(5,2);
ALTER TABLE remediation_campaigns
    DROP COLUMN IF EXISTS last_reconciled_at,
    DROP COLUMN IF EXISTS version;
