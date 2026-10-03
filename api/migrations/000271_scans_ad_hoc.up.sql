-- Quick scans that were never saved (Scans P0, owner decision D10).
--
-- A quick scan runs right away on typed targets. It still needs a scans row
-- for its runs to belong to, but it is not a configuration: ad_hoc = true
-- keeps it out of the Configurations list and the scan counts until someone
-- saves it (POST /scans/{id}/save). Quick scans no longer create an asset
-- group either; their targets live on the scan.
--
-- Additive; existing rows stay configurations (ad_hoc = false), including the
-- "Quick Scan - <timestamp>" rows earlier quick scans left behind.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS ad_hoc BOOLEAN NOT NULL DEFAULT false;
