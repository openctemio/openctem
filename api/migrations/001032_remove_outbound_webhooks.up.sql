-- Remove the outbound webhooks feature (owner decision B9).
--
-- /api/v1/webhooks stored endpoints and secrets, but no delivery worker ever
-- existed: nothing was sent and nothing wrote webhook_deliveries. Notification
-- channels and the SIEM integration cover outbound delivery. The routes and
-- code are removed; this removes the three permissions that gated them.
--
-- The catalog rows and their role grants are copied into
-- access_control_removed_archive first; the down migration restores them.
-- The webhooks / webhook_deliveries tables are kept as they are (no data is
-- destroyed here); they are no longer read or written.

CREATE TEMP TABLE IF NOT EXISTS outbound_webhook_permission_ids (id VARCHAR(100) PRIMARY KEY);
INSERT INTO outbound_webhook_permission_ids (id) VALUES
    ('integrations:webhooks:read'),
    ('integrations:webhooks:write'),
    ('integrations:webhooks:delete')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS access_control_removed_archive (
    id           BIGSERIAL PRIMARY KEY,
    source_table TEXT        NOT NULL,
    row_data     JSONB       NOT NULL,
    archived_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'permissions:001032', to_jsonb(t) FROM permissions t
WHERE t.id IN (SELECT id FROM outbound_webhook_permission_ids);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'role_permissions:001032', to_jsonb(t) FROM role_permissions t
WHERE t.permission_id IN (SELECT id FROM outbound_webhook_permission_ids);

-- role_permissions rows go with the catalog rows (ON DELETE CASCADE).
DELETE FROM permissions WHERE id IN (SELECT id FROM outbound_webhook_permission_ids);

COMMENT ON TABLE webhooks IS 'Retired (owner decision B9): outbound webhooks never had a delivery worker; no code reads or writes this table.';

-- The integrations.webhooks module toggle switched the removed feature on and
-- off; it is deprecated the same way 000187 retired the legacy duplicates
-- (inactive, out of the module picker; the row and any overrides stay).
UPDATE modules
SET is_active = FALSE,
    release_status = 'deprecated'
WHERE id = 'integrations.webhooks';
