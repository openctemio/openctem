-- expand-contract-ok: contract step; no released code writes asset_sources, and the only reader (the asset lifecycle worker's provenance check) reads assets.discovery_source since the previous change.
-- Drop asset_sources (legacy cleanup).
--
-- asset_sources was meant to record which data source reported each asset.
-- Its repository was never constructed, so nothing ever wrote it: the
-- production restore holds 4 rows, all created on one day (2026-04-24) by
-- hand. The one reader was the asset lifecycle worker, which required a row
-- here before demoting an asset and so never demoted anything; it now takes
-- provenance from assets.discovery_source and the clock from
-- assets.last_seen. The asset merge stops moving its rows in the same change.
--
-- The 4 rows carry no information the asset does not (source types
-- scanner / integration / manual / collector with no source id and empty
-- contributed data) and are dropped with the table (owner decision). The down
-- migration recreates the empty table.
--
-- Tenant isolation: unchanged. The table has no tenant column and no RLS
-- policy; it was reached only through assets.

DROP TABLE IF EXISTS asset_sources;
