-- Scan intensity (docs/rfcs/RFC-071-scan-intensity.md): the probe ceiling of
-- a scan, chosen when it is created and copied to each run. passive = T0 (no
-- packets from our sensors to the target hosts), active = T1 (non-intrusive
-- probing), intrusive = T2.
--
-- Existing scans get the tier their tool or workflow already probes at, so no
-- scan changes behaviour: a single-scanner scan takes its tool's tier, a
-- workflow scan the highest tier among its steps (a step names a tool or a
-- capability; the tiers are the scan-stage catalog's). A tool or capability
-- the catalog does not know counts as active, as the dispatch gate treats it.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS intensity TEXT NOT NULL DEFAULT 'active';

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_intensity;
ALTER TABLE scans ADD CONSTRAINT chk_scans_intensity
    CHECK (intensity IN ('passive', 'active', 'intrusive')) NOT VALID;
ALTER TABLE scans VALIDATE CONSTRAINT chk_scans_intensity;

CREATE OR REPLACE FUNCTION pg_temp.intensity_tier(tool TEXT, caps TEXT[]) RETURNS INT
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN lower(coalesce(tool, '')) = 'zap' OR 'dast.web' = ANY (coalesce(caps, '{}')) THEN 2
        WHEN coalesce(tool, '') <> '' THEN
            CASE WHEN lower(tool) IN ('subfinder', 'dnsx', 'betterleaks', 'trufflehog', 'gitleaks', 'semgrep', 'codeql',
                                      'trivy', 'osv-scanner', 'grype', 'checkov', 'kics') THEN 0 ELSE 1 END
        WHEN cardinality(coalesce(caps, '{}')) > 0
             AND caps <@ ARRAY['discover.subdomains', 'resolve.dns', 'secrets.code', 'sast.code', 'sca.deps',
                              'iac.misconfig', 'container.image']::text[] THEN 0
        ELSE 1
    END
$$;

UPDATE scans s
SET intensity = CASE pg_temp.intensity_tier(s.scanner_name, NULL)
        WHEN 0 THEN 'passive' WHEN 2 THEN 'intrusive' ELSE 'active' END
WHERE s.scan_type = 'single';

UPDATE scans s
SET intensity = CASE coalesce((
        SELECT max(pg_temp.intensity_tier(st.tool, st.capabilities))
        FROM scan_workflow_steps st
        WHERE st.scan_workflow_id = s.scan_workflow_id
    ), 1)
        WHEN 0 THEN 'passive' WHEN 2 THEN 'intrusive' ELSE 'active' END
WHERE s.scan_type = 'workflow';

COMMENT ON COLUMN scans.intensity IS 'Probe ceiling of every run (RFC-071): passive (T0), active (T1) or intrusive (T2). A tool or step above it is refused at save and never dispatched.';
