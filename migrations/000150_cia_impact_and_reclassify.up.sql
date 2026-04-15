-- Migration 000150: CIA Impact fields on assets + MITRE technique on findings
--
-- Separate Confidentiality/Integrity/Availability impact ratings per ctem.org requirement.
-- Also add mitre_technique_id to findings for ATT&CK coverage analysis.

-- CIA impact on assets (separate from single business_impact_score)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS confidentiality_impact VARCHAR(10)
  CHECK (confidentiality_impact IS NULL OR confidentiality_impact IN ('none','low','moderate','high'));
ALTER TABLE assets ADD COLUMN IF NOT EXISTS integrity_impact VARCHAR(10)
  CHECK (integrity_impact IS NULL OR integrity_impact IN ('none','low','moderate','high'));
ALTER TABLE assets ADD COLUMN IF NOT EXISTS availability_impact VARCHAR(10)
  CHECK (availability_impact IS NULL OR availability_impact IN ('none','low','moderate','high'));

-- Environment field on assets
ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment VARCHAR(20)
  CHECK (environment IS NULL OR environment IN ('production','staging','development','testing','dr'));

-- MITRE ATT&CK technique on findings (for coverage analysis)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_findings_mitre
  ON findings(mitre_technique_id) WHERE mitre_technique_id IS NOT NULL;
