-- Validates the findings → assets foreign key added NOT VALID by 000378. It
-- scans findings under SHARE UPDATE EXCLUSIVE, which does not block reads or
-- writes. One statement per file.
ALTER TABLE findings VALIDATE CONSTRAINT findings_asset_id_fkey;
