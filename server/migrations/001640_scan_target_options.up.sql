-- RFC-068: how each run resolves the selectors among a scan's targets
-- (wildcard domains, CIDRs) against the inventory. {} is the default
-- (CIDRs swept, non-stale assets, no freshness window). A constant default
-- adds the column without rewriting the table.
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS target_options jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE scans
    ADD CONSTRAINT chk_scans_target_options_object CHECK (jsonb_typeof(target_options) = 'object') NOT VALID;
ALTER TABLE scans VALIDATE CONSTRAINT chk_scans_target_options_object;
