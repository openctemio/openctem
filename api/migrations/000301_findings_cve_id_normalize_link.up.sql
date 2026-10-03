-- findings.cve_id: room for every advisory id, one case, and the catalog link
-- (RFC-044 P0).
--
-- expand-contract-ok: widening VARCHAR(20) to VARCHAR(30) is metadata-only in PostgreSQL (no rewrite) and every old pod's value still fits
--
-- 1. VARCHAR(20) could not hold advisory ids scanners put in cve_id (trivy
--    reports GHSA/RUSTSEC/DLA ids there; openSUSE-SU-2023:0123-1 is 23
--    characters), and one too long failed the whole insert batch. 30 matches
--    vulnerabilities.cve_id.
ALTER TABLE findings ALTER COLUMN cve_id TYPE VARCHAR(30);

-- 2. The catalog, EPSS and KEV key on the upper-case id; ingest and the
--    classify API now store that form. Existing rows follow.
UPDATE findings
SET cve_id = NULLIF(UPPER(TRIM(cve_id)), '')
WHERE cve_id IS NOT NULL
  AND cve_id IS DISTINCT FROM NULLIF(UPPER(TRIM(cve_id)), '');

-- 3. Unlinked findings are the ones the catalog step looks for when a report
--    names their CVE; this keeps that lookup to them.
CREATE INDEX IF NOT EXISTS idx_findings_unlinked_cve
    ON findings (cve_id)
    WHERE vulnerability_id IS NULL AND cve_id IS NOT NULL;

-- 4. Link findings whose CVE is cataloged but that were never linked
--    (stored by protocol v2 before the entry existed, classified by hand,
--    pentest findings).
UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.vulnerability_id IS NULL
  AND f.cve_id IS NOT NULL
  AND v.cve_id = f.cve_id;
