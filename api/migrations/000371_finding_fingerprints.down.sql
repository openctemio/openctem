DROP TRIGGER IF EXISTS trg_findings_fingerprint_alias_update ON findings;
DROP TRIGGER IF EXISTS trg_findings_fingerprint_alias_insert ON findings;
DROP FUNCTION IF EXISTS findings_fingerprint_alias_on_update();
DROP FUNCTION IF EXISTS findings_fingerprint_alias_on_insert();
DROP TABLE IF EXISTS finding_fingerprints;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_fingerprint_version;
ALTER TABLE findings DROP COLUMN IF EXISTS identity_key;
ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint_version;
