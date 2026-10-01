-- 000233 is a data correction. The values it cleared were written by tenant
-- input into catalogs every tenant shares, which is the defect it fixes, so
-- they are deliberately not restored: rolling the code back makes ingest
-- write them again on the next scans.
--
-- The license copy is undone for rows whose license still equals exactly what
-- the migration derived from component_licenses.
UPDATE asset_components ac
SET license = NULL
FROM (
    SELECT component_id, LEFT(string_agg(license_id, ', ' ORDER BY license_id), 255) AS licenses
    FROM component_licenses
    GROUP BY component_id
) l
WHERE l.component_id = ac.component_id
  AND ac.license = l.licenses;
