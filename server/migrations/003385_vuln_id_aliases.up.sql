-- Vulnerability id aliases from the signed vulnerability feed
-- (docs/architecture/deduplication.md, "Canonical vulnerability ids").
--
-- One row per advisory id (GHSA, or an OSV ecosystem id such as PYSEC- or
-- GO-) that the feed's alias data ties to exactly one CVE. Ingest keys a
-- finding that names only such an id on the CVE, so two tools that name one
-- vulnerability differently report one finding. Platform-wide public data
-- (no tenant column), written only by the bundle importer from a signed
-- manifest; an advisory whose aliases name two CVEs is never listed, so two
-- CVEs are never fused.

CREATE TABLE IF NOT EXISTS vuln_id_aliases (
    alias_id   text        NOT NULL,
    cve_id     text        NOT NULL,
    source     varchar(8)  NOT NULL,
    version    bigint      NOT NULL,
    synced_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_vuln_id_aliases PRIMARY KEY (alias_id),
    CONSTRAINT chk_vuln_id_aliases_alias CHECK (length(alias_id) BETWEEN 5 AND 64 AND alias_id !~ '^CVE-'
        AND alias_id ~ '^[A-Z][A-Z0-9]*-[A-Za-z0-9._:-]+$'),
    CONSTRAINT chk_vuln_id_aliases_cve CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    CONSTRAINT chk_vuln_id_aliases_source CHECK (source IN ('ghsa', 'osv')),
    CONSTRAINT chk_vuln_id_aliases_version CHECK (version > 0)
);
CREATE INDEX IF NOT EXISTS idx_vuln_id_aliases_cve ON vuln_id_aliases (cve_id);
COMMENT ON TABLE vuln_id_aliases IS
    'Advisory id (GHSA or OSV ecosystem id) -> the one CVE the signed feed aliases it to. Written only by the bundle importer (full snapshot per version, removal guard); read by ingest to choose a finding''s canonical vulnerability id. Public data, no tenant.';
