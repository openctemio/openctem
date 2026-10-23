-- Reverts 003364_quarantine_apply_claim.
ALTER TABLE sensor_result_quarantine DROP COLUMN IF EXISTS applying_at;
