DROP INDEX IF EXISTS idx_findings_mitre;
ALTER TABLE findings DROP COLUMN IF EXISTS mitre_tactic;
ALTER TABLE findings DROP COLUMN IF EXISTS mitre_technique_id;
ALTER TABLE assets DROP COLUMN IF EXISTS environment;
ALTER TABLE assets DROP COLUMN IF EXISTS availability_impact;
ALTER TABLE assets DROP COLUMN IF EXISTS integrity_impact;
ALTER TABLE assets DROP COLUMN IF EXISTS confidentiality_impact;
