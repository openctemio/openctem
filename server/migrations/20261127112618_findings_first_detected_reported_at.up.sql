-- findings_first_detected_reported_at (up)
-- The earliest first-seen time a producer reported for the finding
-- (CTIS first_seen_at, bounded at ingest). first_detected_at may come from
-- it; created_at stays the platform's own receipt. NULL when no producer
-- said. Nullable without a default: no table rewrite.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_detected_reported_at TIMESTAMPTZ;

COMMENT ON COLUMN findings.first_detected_reported_at IS
    'Earliest first-seen time a producer reported (producer-supplied, bounded); first_detected_at may come from it, created_at is the receipt';
