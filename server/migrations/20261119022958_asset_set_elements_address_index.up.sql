-- research/531: an address inside a shared provider range is recorded on the
-- names that resolve to it (their ip_addresses set elements), not as an
-- address asset. Searching the inventory for an address finds those names,
-- current and past, through this index (tenant, address).
--
-- Live impact: built CONCURRENTLY (no write lock on the table); the only
-- statement in this file because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_set_elements_tenant_address
    ON asset_attribute_set_elements (tenant_id, element) WHERE attribute = 'ip_addresses';
