-- Schedule misfire made visible (research/468 D17, P0-9): when the scheduler skips an
-- occurrence that was missed by more than one interval, the scan keeps when and why.
-- Two nullable columns, no default, no backfill: a metadata-only change, no table rewrite.
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS last_missed_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_missed_reason varchar(64);
