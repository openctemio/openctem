-- RFC-026 (docs/rfcs/RFC-026-sensor-results-ingest.md) WP-A5: per-report item
-- totals of protocol v2 results. Expand only.
--
-- A v2 report may carry at most 100,000 assets and 100,000 findings over all
-- its segments (RFC-026 §3.6). The accept path reserves a segment's counts
-- with one conditional UPDATE before it queues the segment, so parallel
-- segments cannot overshoot the limit.
ALTER TABLE ingest_reports ADD COLUMN IF NOT EXISTS assets_received INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_reports ADD COLUMN IF NOT EXISTS findings_received INT NOT NULL DEFAULT 0;

ALTER TABLE ingest_reports DROP CONSTRAINT IF EXISTS ingest_reports_item_totals_check;
ALTER TABLE ingest_reports ADD CONSTRAINT ingest_reports_item_totals_check
    CHECK (assets_received >= 0 AND findings_received >= 0);
