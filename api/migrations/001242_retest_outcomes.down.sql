ALTER TABLE finding_retests DROP CONSTRAINT IF EXISTS chk_finding_retests_reason_code;
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_outcome;
UPDATE finding_retests SET outcome = CASE outcome
        WHEN 'confirmed_fixed' THEN 'fixed'
        WHEN 'not_reproduced' THEN 'fixed'
        WHEN 'still_vulnerable' THEN 'still_present'
        WHEN 'inconclusive' THEN 'unknown'
        ELSE outcome END
WHERE outcome IS NOT NULL;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_outcome CHECK (
    outcome IS NULL OR outcome IN ('fixed', 'still_present', 'unknown'));
ALTER TABLE finding_retests DROP COLUMN reason_code;
ALTER TABLE finding_retests DROP COLUMN IF EXISTS sensor_id;
