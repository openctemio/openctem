-- web_content_p0 (down)
DROP TABLE IF EXISTS web_alert_fingerprints;
DROP TABLE IF EXISTS web_endpoint_verifications;

-- A web_verify scan has no place under the old CHECK: it becomes an
-- ordinary ad hoc scan (its runs keep their rows).
UPDATE scans SET managed_by = NULL, managed_key = NULL WHERE managed_by = 'web_verify';
ALTER TABLE scans DROP CONSTRAINT scans_managed_by_check;
ALTER TABLE scans
    ADD CONSTRAINT scans_managed_by_check CHECK (
        (managed_by IS NULL AND managed_key IS NULL)
        OR (managed_by IN ('coverage', 'enrichment') AND managed_key IS NOT NULL AND managed_key <> '')
    );
