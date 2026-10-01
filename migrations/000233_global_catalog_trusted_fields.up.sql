-- The shared catalogs (vulnerabilities, components, component_licenses) are
-- read by every tenant, but tenant input could write them: a sensor report
-- filled blanks and OR-ed exploit_available on any CVE, and a license a
-- tenant's sensor declared was attached to the shared component for everyone.
-- From this release tenant input never changes those shared fields
-- (docs/architecture/global-catalog-trust.md). This migration corrects the
-- data already written.

-- 1. Risk signals on the CVE catalog come only from the EPSS and CISA KEV
--    feeds. Clear what tenant ingest wrote, then rebuild from the feeds (the
--    same statements ThreatIntelRepository.PropagateToVulnerabilityCatalog
--    runs after every sync).
UPDATE vulnerabilities
SET epss_score = NULL,
    epss_percentile = NULL,
    cisa_kev_date_added = NULL,
    cisa_kev_due_date = NULL,
    cisa_kev_ransomware_use = NULL,
    cisa_kev_notes = NULL,
    exploit_available = false,
    exploit_maturity = 'none'
WHERE epss_score IS NOT NULL
   OR epss_percentile IS NOT NULL
   OR cisa_kev_date_added IS NOT NULL
   OR cisa_kev_due_date IS NOT NULL
   OR cisa_kev_ransomware_use IS NOT NULL
   OR cisa_kev_notes IS NOT NULL
   OR exploit_available
   OR exploit_maturity <> 'none';

UPDATE vulnerabilities v
SET epss_score = e.epss_score, epss_percentile = e.percentile
FROM epss_scores e
WHERE e.cve_id = v.cve_id;

UPDATE vulnerabilities v
SET cisa_kev_date_added     = k.date_added::timestamptz,
    cisa_kev_due_date       = k.due_date::timestamptz,
    cisa_kev_ransomware_use = k.known_ransomware_campaign_use,
    cisa_kev_notes          = k.notes,
    exploit_available       = true
FROM kev_catalog k
WHERE k.cve_id = v.cve_id;

-- 2. Licenses are a tenant observation, stored on the tenant's own
--    asset_components.license. Carry the links that exist today onto each
--    tenant's rows that have no license yet, so license reports do not go
--    empty. They cannot be attributed to the tenant that declared them, so
--    every tenant keeps exactly what it saw before; new scans then record
--    only their own. component_licenses is left in place and no longer read.
UPDATE asset_components ac
SET license = LEFT(l.licenses, 255)
FROM (
    SELECT component_id, string_agg(license_id, ', ' ORDER BY license_id) AS licenses
    FROM component_licenses
    GROUP BY component_id
) l
WHERE l.component_id = ac.component_id
  AND COALESCE(ac.license, '') = '';
