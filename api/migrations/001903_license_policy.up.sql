-- License policy (RFC-070 §9): the verdict of the organization's license
-- policy on each package link, and a "license" finding type for violations.

ALTER TABLE asset_software
    ADD COLUMN license_verdict TEXT CHECK (license_verdict IN ('allow', 'review', 'deny')),
    ADD COLUMN license_rule    TEXT CHECK (length(license_rule) <= 160);
COMMENT ON COLUMN asset_software.license_verdict IS
    'Verdict of the tenant license policy on the link''s licenses (NULL: policy off or not evaluated yet).';
COMMENT ON COLUMN asset_software.license_rule IS
    'What decided the verdict: the rule''s match, "default" or "unknown".';
CREATE INDEX idx_asset_software_license_verdict ON asset_software (tenant_id, license_verdict)
    WHERE source = 'package' AND license_verdict IN ('review', 'deny');

-- A broader check: existing rows already satisfy it, so it is added
-- NOT VALID and validated without blocking writes.
ALTER TABLE findings DROP CONSTRAINT chk_finding_type;
ALTER TABLE findings ADD CONSTRAINT chk_finding_type CHECK (finding_type IS NULL OR finding_type IN
    ('vulnerability', 'secret', 'misconfiguration', 'compliance', 'web3', 'license')) NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_finding_type;
