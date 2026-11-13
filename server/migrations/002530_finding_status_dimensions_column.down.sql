ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_observation_state;
ALTER TABLE findings DROP COLUMN IF EXISTS observation_state;
