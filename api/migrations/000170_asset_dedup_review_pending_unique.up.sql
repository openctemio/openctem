-- Enable idempotent enqueue of duplicate-asset reviews: at most one PENDING
-- review per (tenant, keep asset). Lets the ingest correlator UPSERT a review
-- when it detects multiple existing assets sharing identity, without piling up
-- duplicate pending rows on every scan. Resolved/rejected/merged rows are not
-- constrained (the partial WHERE), so history is preserved.
CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_dedup_review_pending
    ON asset_dedup_review (tenant_id, keep_asset_id)
    WHERE status = 'pending';
