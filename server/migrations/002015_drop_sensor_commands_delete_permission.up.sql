-- sensors:commands:delete gated only DELETE /api/v1/commands/{id}, removed
-- with the other single-command user routes (read, cancel): a scan run is
-- cancelled as a whole. A permission that gates nothing still shows in the
-- role editor, so it is removed (tests/unit/permission_checked_test.go). No
-- role loses access to anything: no route checks it. Its role grants go with
-- the catalog row (ON DELETE CASCADE); API key scopes and licenses drop the id.

UPDATE api_keys SET scopes = array_remove(scopes, 'sensors:commands:delete')
WHERE 'sensors:commands:delete' = ANY(scopes);
UPDATE licenses SET permissions = array_remove(permissions, 'sensors:commands:delete')
WHERE 'sensors:commands:delete' = ANY(permissions);
DELETE FROM permissions WHERE id IN (
    SELECT id FROM (VALUES
        ('sensors:commands:delete')
    ) AS removed(id)
);
