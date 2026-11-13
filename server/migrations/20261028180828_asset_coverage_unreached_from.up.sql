-- Who observed a coverage pair's target not answering (RFC-093, unreachable
-- targets): "zone:<uuid>" when the task ran for a scan zone, else
-- "sensor:<uuid>"; '' when unknown or after a success. The recheck streak
-- (and its widening wait) goes on only while the same zone or sensor sees
-- the target silent again; another observer starts it over. Never shown to
-- the organization as a platform sensor's identity.
--
-- Live impact: one NOT NULL column with a constant default on
-- asset_coverage (catalog-only change on PostgreSQL 11+, no rewrite, no
-- backfill).

ALTER TABLE asset_coverage
    ADD COLUMN IF NOT EXISTS unreached_from varchar(80) NOT NULL DEFAULT '';
