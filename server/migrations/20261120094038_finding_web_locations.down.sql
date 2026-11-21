-- Removes the finding web locations (derived from ingest; the finding rows
-- keep their own location and fingerprint).
DROP TABLE IF EXISTS finding_web_locations;
