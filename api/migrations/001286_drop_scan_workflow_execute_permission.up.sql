-- integrations:pipelines:execute gated only the direct run of a scan workflow
-- (POST /pipelines/{id}/runs), which is removed: a scan run starts only by
-- triggering a Scan, through the scan gate (scope, freeze, sensors, tools).
-- A permission that gates nothing still shows in the role editor, so it is
-- removed (tests/unit/permission_checked_test.go). No role loses access to
-- anything: no route checks it.
--
-- The catalog row, its role grants and its backfill-ledger rows are copied,
-- as JSON, into access_control_removed_archive first; the down migration
-- restores them. API key scopes and licenses drop the id (nothing checks it).

CREATE TEMP TABLE IF NOT EXISTS removed_permission_ids_001286 (id VARCHAR(100) PRIMARY KEY);
INSERT INTO removed_permission_ids_001286 (id) VALUES
    ('integrations:pipelines:execute')
ON CONFLICT DO NOTHING;

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'permissions:001286', to_jsonb(t) FROM permissions t
WHERE t.id IN (SELECT id FROM removed_permission_ids_001286);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'role_permissions:001286', to_jsonb(t) FROM role_permissions t
WHERE t.permission_id IN (SELECT id FROM removed_permission_ids_001286);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'granular_permission_backfill:001286', to_jsonb(t) FROM granular_permission_backfill t
WHERE t.permission_id IN (SELECT id FROM removed_permission_ids_001286);

DELETE FROM granular_permission_backfill WHERE permission_id IN (SELECT id FROM removed_permission_ids_001286);
UPDATE api_keys SET scopes = array_remove(scopes, 'integrations:pipelines:execute')
WHERE 'integrations:pipelines:execute' = ANY(scopes);
UPDATE licenses SET permissions = array_remove(permissions, 'integrations:pipelines:execute')
WHERE 'integrations:pipelines:execute' = ANY(permissions);

-- role_permissions rows go with the catalog row (ON DELETE CASCADE).
DELETE FROM permissions WHERE id IN (SELECT id FROM removed_permission_ids_001286);
