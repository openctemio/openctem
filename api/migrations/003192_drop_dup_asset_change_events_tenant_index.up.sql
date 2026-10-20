-- idx_asset_change_events_tenant (tenant_id, at DESC, id DESC) is the primary key
-- (tenant_id, at, id) read backwards; every change event and every partition kept both.
-- CONCURRENTLY is not available on a partitioned parent, so the drop is brief and bounded.
SET LOCAL lock_timeout = '5s';
DROP INDEX IF EXISTS idx_asset_change_events_tenant;
