-- Finding imports (docs/architecture/finding-import.md): who produced the
-- results a person imported from another tool, so every stored result has a
-- producer, as sensor results have their sensor and CI results their run.
--
--   finding_imports   one row per imported file (never for a preview): the
--                     uploader, the format, a SHA-256 of the file name (the
--                     name itself is not stored here), and the counts
--   findings.scan_id  set to the import id by ingest (the report id), as for
--                     a scan
--   assets.import_id  the last import that created or updated the asset
--
-- Live impact: one new table and one nullable column on assets (metadata-only,
-- no rewrite, no backfill). The partial index covers no row yet.

CREATE TABLE IF NOT EXISTS finding_imports (
    id                UUID         PRIMARY KEY,
    tenant_id         UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_user_id     UUID         REFERENCES users(id) ON DELETE SET NULL,
    format            VARCHAR(32)  NOT NULL,
    filename_sha256   CHAR(64)     NOT NULL,
    assets_created    INTEGER      NOT NULL DEFAULT 0,
    assets_updated    INTEGER      NOT NULL DEFAULT 0,
    findings_created  INTEGER      NOT NULL DEFAULT 0,
    findings_updated  INTEGER      NOT NULL DEFAULT 0,
    components        INTEGER      NOT NULL DEFAULT 0,
    statements        INTEGER      NOT NULL DEFAULT 0,
    skipped           INTEGER      NOT NULL DEFAULT 0,
    vex_stored        INTEGER      NOT NULL DEFAULT 0,
    vex_closed        INTEGER      NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_finding_imports_sha CHECK (filename_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_finding_imports_counts CHECK (
        assets_created >= 0 AND assets_updated >= 0 AND findings_created >= 0 AND findings_updated >= 0
        AND components >= 0 AND statements >= 0 AND skipped >= 0 AND vex_stored >= 0 AND vex_closed >= 0)
);

CREATE INDEX IF NOT EXISTS idx_finding_imports_tenant_created ON finding_imports (tenant_id, created_at DESC);

COMMENT ON TABLE finding_imports IS 'One row per file a person imported (POST /findings/import, never a preview): the producer of the findings whose scan_id and the assets whose import_id is this id.';
COMMENT ON COLUMN finding_imports.filename_sha256 IS 'SHA-256 of the uploaded file name; the name itself is kept only in the audit log.';

ALTER TABLE assets ADD COLUMN IF NOT EXISTS import_id UUID;
COMMENT ON COLUMN assets.import_id IS 'The last finding import (finding_imports.id) that created or updated this asset. No foreign key: purging an import record must not touch assets.';
CREATE INDEX IF NOT EXISTS idx_assets_tenant_import ON assets (tenant_id, import_id) WHERE import_id IS NOT NULL;
