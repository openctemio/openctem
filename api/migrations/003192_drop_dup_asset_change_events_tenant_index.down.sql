CREATE INDEX IF NOT EXISTS idx_asset_change_events_tenant ON asset_change_events (tenant_id, at DESC, id DESC);
