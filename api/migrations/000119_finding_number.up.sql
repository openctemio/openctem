-- Human-readable finding number per campaign (e.g., PROJ-001).
-- Auto-incremented within each campaign (not globally unique).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_number INT;

-- Index for fast MAX() query when creating new findings
CREATE INDEX IF NOT EXISTS idx_findings_campaign_number
    ON findings(pentest_campaign_id, finding_number DESC)
    WHERE pentest_campaign_id IS NOT NULL AND finding_number IS NOT NULL;

-- Backfill existing pentest findings with sequential numbers per campaign
DO $$
DECLARE
    r RECORD;
    num INT;
BEGIN
    FOR r IN
        SELECT DISTINCT pentest_campaign_id
        FROM findings
        WHERE pentest_campaign_id IS NOT NULL AND finding_number IS NULL
    LOOP
        num := 0;
        UPDATE findings f SET finding_number = sub.rn
        FROM (
            SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) AS rn
            FROM findings
            WHERE pentest_campaign_id = r.pentest_campaign_id
        ) sub
        WHERE f.id = sub.id;
    END LOOP;
END $$;
