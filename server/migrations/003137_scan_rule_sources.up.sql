-- Rule sources (docs/architecture/rule-sources.md): which detection rules a
-- scan runs, the platform's, the organization's own templates, or both
-- together. A scan's NULL inherits its profile's; a profile defaults to
-- both, which is what every existing scan already ran. Constant defaults
-- and nullable columns only: no table rewrite, no backfill.

ALTER TABLE scan_profiles
    ADD COLUMN IF NOT EXISTS rule_sources VARCHAR(16) NOT NULL DEFAULT 'both';
ALTER TABLE scan_profiles
    DROP CONSTRAINT IF EXISTS scan_profiles_rule_sources_check;
ALTER TABLE scan_profiles
    ADD CONSTRAINT scan_profiles_rule_sources_check
    CHECK (rule_sources IN ('both', 'platform', 'tenant'));

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS rule_sources VARCHAR(16);
ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_rule_sources_check;
ALTER TABLE scans
    ADD CONSTRAINT scans_rule_sources_check
    CHECK (rule_sources IS NULL OR rule_sources IN ('both', 'platform', 'tenant'));

COMMENT ON COLUMN scan_profiles.rule_sources IS 'Detection rules the profile''s scans run: both, platform or tenant';
COMMENT ON COLUMN scans.rule_sources IS 'Detection rules the scan runs: both, platform or tenant; NULL inherits the profile''s';
