-- Progress of the job that links stored technologies whose version is hidden
-- to the software inventory (docs/architecture/vulnerability-matching.md,
-- "Version hidden"). One row per tenant: the position the last batch reached
-- (asset id, technology key), so a stopped run resumes there, and when the
-- tenant was finished at a job version. A new table: nothing is locked or
-- rewritten on the populated ones.
CREATE TABLE asset_software_versionless_backfill (
    tenant_id    UUID        NOT NULL PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version      INTEGER     NOT NULL CHECK (version > 0),
    after_asset  UUID,
    after_key    VARCHAR(128) NOT NULL DEFAULT '',
    linked       INTEGER     NOT NULL DEFAULT 0 CHECK (linked >= 0),
    completed_at TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE asset_software_versionless_backfill IS
    'Per-tenant progress of linking stored version-less technologies of curated public products to asset_software.';
