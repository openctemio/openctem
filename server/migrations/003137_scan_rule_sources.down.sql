ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_rule_sources_check;
ALTER TABLE scans DROP COLUMN IF EXISTS rule_sources;
ALTER TABLE scan_profiles DROP CONSTRAINT IF EXISTS scan_profiles_rule_sources_check;
ALTER TABLE scan_profiles DROP COLUMN IF EXISTS rule_sources;
