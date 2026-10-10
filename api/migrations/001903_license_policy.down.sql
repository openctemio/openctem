-- License findings have no type before this migration: they become
-- compliance findings.
UPDATE findings SET finding_type = 'compliance' WHERE finding_type = 'license';
ALTER TABLE findings DROP CONSTRAINT chk_finding_type;
ALTER TABLE findings ADD CONSTRAINT chk_finding_type CHECK (finding_type IS NULL OR finding_type IN
    ('vulnerability', 'secret', 'misconfiguration', 'compliance', 'web3'));
DROP INDEX IF EXISTS idx_asset_software_license_verdict;
ALTER TABLE asset_software DROP COLUMN IF EXISTS license_rule, DROP COLUMN IF EXISTS license_verdict;
