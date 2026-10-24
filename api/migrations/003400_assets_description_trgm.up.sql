-- Asset list search: trigram index on assets(description). The search box
-- matches "name ILIKE OR description ILIKE OR aliases ?" (asset_repository.go);
-- without an index on description that OR cannot be a BitmapOr and every
-- search read all of the tenant's assets (75 ms at 100k assets, 0.3 ms with
-- the index; research note 255).
--
-- Live impact: built CONCURRENTLY (no write lock on assets); the only
-- statement in this file because CONCURRENTLY cannot run inside a
-- transaction. Build time grows with the table size.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_description_trgm ON assets USING gin (description gin_trgm_ops);
