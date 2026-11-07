-- findings.cvss_vector holds a whole CVSS vector.
--
-- The column was varchar(100). A CVSS 4.0 vector with threat, environmental
-- and supplemental metrics is up to 178 characters (a CVSS 3.1 vector with
-- temporal and environmental metrics passes 100 too), so every finding
-- scored with one failed to store: the version matcher's findings of such
-- CVEs were counted as failed on each pass, and a scanner or pentest finding
-- carrying one failed the same way. The catalog keeps vectors up to 200
-- characters (cve_records, vulnerabilities) and the pentest API accepts 255,
-- so the column takes 255.
--
-- Live impact: widening a varchar is a catalog change only (no table
-- rewrite, no scan); the lock is brief, and the timeout fails the migration
-- instead of queueing writes behind a busy table.

SET LOCAL lock_timeout = '5s';

-- expand-contract-ok: widening varchar(100) to varchar(255) only; old pods read and write the column unchanged, and Postgres changes only the catalog
ALTER TABLE findings ALTER COLUMN cvss_vector TYPE character varying(255);
