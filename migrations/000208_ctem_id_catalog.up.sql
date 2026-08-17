-- CTEM-ID catalog: a standardized, CVE-like reference catalog of exposure
-- classes (brand impersonation, credential dumps, infected devices, lookalike
-- domains, ransomware, source-code exposure, system exposure, ...). Populated
-- from an external JSON feed (default https://ctem.org/source.json) on a daily
-- fail-open refresh. This is TENANT-AGNOSTIC reference data (like kev_catalog /
-- epss_scores): there is no tenant_id column. Findings and exposures reference a
-- ctem_id as a tag.
CREATE TABLE IF NOT EXISTS ctem_id_catalog (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ctem_id      TEXT NOT NULL UNIQUE,
    category     TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    source_url   TEXT NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ,
    raw          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
