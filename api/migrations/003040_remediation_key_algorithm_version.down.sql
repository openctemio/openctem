-- Expired suggestions stay expired: the next generator run proposes again
-- whatever the keys support.
ALTER TABLE finding_remediation_keys DROP COLUMN IF EXISTS algorithm_version;
