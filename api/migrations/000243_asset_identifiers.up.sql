-- Asset identity model (docs/architecture/asset-identity-resolution.md).
-- Expand only: two new tables, two nullable columns on asset_dedup_review,
-- and one more allowed value in the asset_state_history change_type check.

-- Identifiers an asset was seen with. Strong kinds (host ID, cloud ID, BIOS
-- UUID, serial, MAC, SCM repository ID) identify one asset per tenant and are
-- unique per tenant. FQDN, hostname and IP are attributes several assets can
-- share over time; last_seen bounds how long an IP still counts as evidence.
CREATE TABLE IF NOT EXISTS asset_identifiers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind        VARCHAR(32) NOT NULL,
    value       VARCHAR(512) NOT NULL,
    -- Set from kind; the partial unique index below needs a plain column.
    strong      BOOLEAN NOT NULL,
    -- Tool that reported it, or 'backfill' / 'manual'.
    source      VARCHAR(100) NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_asset_identifiers_kind CHECK (kind IN (
        'host_id', 'cloud_id', 'bios_uuid', 'serial_number', 'mac', 'scm_repo_id',
        'fqdn', 'hostname', 'ip'
    )),
    CONSTRAINT chk_asset_identifiers_strong CHECK (
        strong = (kind IN ('host_id', 'cloud_id', 'bios_uuid', 'serial_number', 'mac', 'scm_repo_id'))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_identifiers_strong
    ON asset_identifiers (tenant_id, kind, value) WHERE strong;
CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_identifiers_asset
    ON asset_identifiers (asset_id, kind, value);
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_lookup
    ON asset_identifiers (tenant_id, kind, value);

COMMENT ON TABLE asset_identifiers IS
    'Identifiers an asset was seen with; strong kinds are unique per tenant (asset identity model)';

-- Why a duplicate review was raised, and the evidence, so the reviewer sees
-- the shared identifier instead of only two names. NULL for older reviews.
ALTER TABLE asset_dedup_review ADD COLUMN IF NOT EXISTS reason VARCHAR(40);
ALTER TABLE asset_dedup_review ADD COLUMN IF NOT EXISTS evidence JSONB;

-- A changed display name is recorded in state history (change_type 'renamed').
-- expand-contract-ok: no rename here; the check matches the value 'renamed' in a widened CHECK, which old code never writes and so cannot break
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS chk_change_type;
ALTER TABLE asset_state_history ADD CONSTRAINT chk_change_type CHECK (change_type IN (
    'appeared', 'disappeared', 'recovered',
    'exposure_changed', 'status_changed',
    'criticality_changed', 'owner_changed', 'compliance_changed',
    'classification_changed', 'internet_exposure_changed',
    'renamed'
));

-- One row per tenant once the identifier backfill job has processed it, so
-- the job does not rescan the inventory on every start. Bumping the job's
-- version reruns it.
CREATE TABLE IF NOT EXISTS asset_identity_backfill (
    tenant_id          UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version            INT NOT NULL,
    assets_scanned     INT NOT NULL DEFAULT 0,
    identifiers_added  INT NOT NULL DEFAULT 0,
    reviews_enqueued   INT NOT NULL DEFAULT 0,
    completed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
