-- One-off (ad-hoc) scans that never ran stop cluttering the scan list.
--
-- 1. scans.archived_at: set by the one-off archive job on an ad-hoc scan
--    that never ran and is older than its threshold. An archived scan is
--    disabled, left out of every scan list, and kept (archived, not deleted)
--    with its audit trail.
-- 2. Quick scans created before ad-hoc scans existed (RFC-046 D10) were
--    stored as ordinary configurations, named by the quick-scan generator
--    ("Quick Scan - YYYYMMDD-HHMMSS..." with the description "Quick scan of
--    N targets"). They are marked ad hoc, so the default list hides them like
--    every later quick scan; "Save as scan" turns one back into a
--    configuration. Only manual scans that still carry both generated values
--    are matched.
--
-- Safe on populated tables: a nullable column, and one UPDATE on the few
-- legacy rows.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
COMMENT ON COLUMN scans.archived_at IS
    'When the one-off archive job archived this ad-hoc scan (never ran, past its threshold); NULL otherwise';

UPDATE scans
SET ad_hoc = true
WHERE ad_hoc = false
  AND schedule_type = 'manual'
  AND name ~ '^Quick Scan - [0-9]{8}-[0-9]{6}'
  AND description ~ '^Quick scan of [0-9]+ targets?$';
