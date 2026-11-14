ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_hold_reasons;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_verification_state;
ALTER TABLE findings DROP COLUMN IF EXISTS hold_reasons, DROP COLUMN IF EXISTS verification_state;
