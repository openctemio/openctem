-- Composite tenant foreign keys on asset references (research doc 21b, P1-1:
-- the database backstop for C1/C3/C4).
--
-- Step 1 of 3: the referenced key. A foreign key on (tenant_id, asset_id)
-- needs a unique index on assets (tenant_id, id). id is already the primary
-- key, so the index can never conflict; it is built CONCURRENTLY so asset
-- writes are not blocked while it builds. One statement per file: CREATE
-- INDEX CONCURRENTLY cannot run inside the implicit transaction of a
-- multi-statement migration.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_assets_tenant_id_id ON assets (tenant_id, id);
