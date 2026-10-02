-- Migration 140: partial composite index supporting ListComponentCVEPairs.
-- Skips rows where component_id or vulnerability_id is NULL (they cannot match
-- the derived Component↔CVE query's JOIN conditions).

CREATE INDEX IF NOT EXISTS idx_findings_tenant_component_vuln
    ON findings (tenant_id, component_id, vulnerability_id)
    WHERE component_id IS NOT NULL AND vulnerability_id IS NOT NULL;
