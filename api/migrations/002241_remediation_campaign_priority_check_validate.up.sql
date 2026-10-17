-- Validates the priority CHECK added NOT VALID by remediation_campaign_version
-- (a separate step, so the add takes no long lock).
ALTER TABLE remediation_campaigns VALIDATE CONSTRAINT chk_remediation_campaigns_priority;
