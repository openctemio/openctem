-- A scan may pin its targets to one scan zone (RFC-023 §7 zone picker).
-- NULL = Automatic: each target goes to the narrowest zone that holds it.
-- No foreign key on purpose: a scan whose zone was deleted must fail its
-- trigger (SCAN_ZONE_NOT_FOUND), never fall back to automatic routing.
-- Deleting a zone that scans still select is refused by the API (409).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_zone_id UUID NULL;

CREATE INDEX IF NOT EXISTS idx_scans_tenant_scan_zone
    ON scans (tenant_id, scan_zone_id)
    WHERE scan_zone_id IS NOT NULL;
