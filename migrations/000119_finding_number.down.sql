DROP INDEX IF EXISTS idx_findings_campaign_number;
ALTER TABLE findings DROP COLUMN IF EXISTS finding_number;
