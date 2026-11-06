-- Targets a user left out when saving a scan because the scope check refused
-- them ("Scan the allowed targets, skip the rest"), with the refusal code:
-- [{"target": "...", "code": "..."}]. Every run of
-- the scan records them. Nullable, no default: instant on a populated table.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS skipped_targets jsonb;
ALTER TABLE scans ADD CONSTRAINT chk_scans_skipped_targets_size
    CHECK (skipped_targets IS NULL OR octet_length(skipped_targets::text) <= 1048576) NOT VALID;
