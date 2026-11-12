-- ctis2_asset_canonical_changes (up)
--
-- CTIS 2.0 canonical forms (IDNA A-labels for host names, RFC 5952 IPv6,
-- dot segments and percent encoding of URL paths, the expanded image digest
-- form) can give a stored asset a different name than ingest gives the same
-- asset now. The asset-canonical runner (internal/app/assetcanon, run on
-- server start and as the asset-canonical command) renames such an asset to
-- its canonical name, or merges it into the asset that already has that name
-- through the asset merge. This table is its journal: one row per asset it
-- renamed, merged or had to leave (another type holds the name). A rename is
-- undone with `asset-canonical -revert`; a merge, like every asset merge, is
-- not undone.

CREATE TABLE IF NOT EXISTS asset_canonical_changes (
    id              uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid         NOT NULL,
    asset_id        uuid         NOT NULL,
    asset_type      varchar(50)  NOT NULL,
    old_name        text         NOT NULL,
    new_name        text         NOT NULL,
    action          varchar(16)  NOT NULL,
    kept_asset_id   uuid,
    reverted_at     timestamptz,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_canonical_changes PRIMARY KEY (id),
    CONSTRAINT fk_asset_canonical_changes_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_canonical_changes_action CHECK (action IN ('rename', 'merge', 'conflict'))
);

COMMENT ON TABLE asset_canonical_changes IS
    'Journal of the CTIS 2.0 asset canonical-name migration: renames (revertible), merges and conflicts per tenant.';

CREATE INDEX IF NOT EXISTS idx_asset_canonical_changes_tenant
    ON asset_canonical_changes (tenant_id, created_at);
-- At most one open conflict per asset and name: a rerun does not pile rows up.
CREATE UNIQUE INDEX IF NOT EXISTS ux_asset_canonical_changes_conflict
    ON asset_canonical_changes (tenant_id, asset_id, new_name) WHERE action = 'conflict';

-- Policy in shadow mode, like the other tenant tables (row security stays off).
DROP POLICY IF EXISTS asset_canonical_changes_tenant_isolation ON asset_canonical_changes;
CREATE POLICY asset_canonical_changes_tenant_isolation ON asset_canonical_changes
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
