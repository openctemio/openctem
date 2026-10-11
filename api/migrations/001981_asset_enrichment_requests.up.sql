-- Automatic enrichment requests (docs/rfcs/RFC-075-asset-freshness.md): one
-- row per asset that should be enriched. Every creation path (ingest, manual
-- create, CSV import) upserts a row; the asset-enrichment controller claims
-- pending rows per tenant, within a daily budget, and starts passive runs of
-- the built-in enrichment profiles.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS asset_enrichment_requests (
    tenant_id     uuid        NOT NULL,
    asset_id      uuid        NOT NULL,
    reason        varchar(20) NOT NULL,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    -- NULL while pending; set when the controller claims the row.
    dispatched_at timestamptz,
    -- What the claim did: dispatched, disabled, no_profile, refused, failed.
    outcome       varchar(20) NOT NULL DEFAULT '',
    attempts      integer     NOT NULL DEFAULT 0,
    last_run_id   uuid,
    CONSTRAINT pk_asset_enrichment_requests PRIMARY KEY (tenant_id, asset_id),
    CONSTRAINT fk_asset_enrichment_requests_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_enrichment_requests_reason
        CHECK (reason IN ('new_asset', 'stale', 'change', 'manual')),
    CONSTRAINT chk_asset_enrichment_requests_outcome
        CHECK (outcome IN ('', 'claimed', 'dispatched', 'disabled', 'no_profile', 'refused', 'failed'))
);

COMMENT ON TABLE asset_enrichment_requests IS
    'RFC-075: pending and last automatic enrichment of an asset (one row per asset).';

-- Pending rows per tenant, oldest first (the controller's claim).
CREATE INDEX IF NOT EXISTS idx_asset_enrichment_requests_pending
    ON asset_enrichment_requests (tenant_id, requested_at) WHERE dispatched_at IS NULL;
-- Dispatched in the last day per tenant (the budget).
CREATE INDEX IF NOT EXISTS idx_asset_enrichment_requests_dispatched
    ON asset_enrichment_requests (tenant_id, dispatched_at) WHERE dispatched_at IS NOT NULL;
