-- assets:components:delete gated only the manual delete of a component link
-- (DELETE /components/{id}), which is removed with the component inventory
-- moving into the software catalog (RFC-070): links are written by sensors,
-- CI and SBOM import, and a wrong link is fixed at its source. A permission
-- that gates nothing still shows in the role editor, so it is removed
-- (tests/unit/permission_checked_test.go). No role loses access to anything:
-- no route checks it. Its role grants go with the catalog row (ON DELETE
-- CASCADE); API key scopes and licenses drop the id.

UPDATE api_keys SET scopes = array_remove(scopes, 'assets:components:delete')
WHERE 'assets:components:delete' = ANY(scopes);
UPDATE licenses SET permissions = array_remove(permissions, 'assets:components:delete')
WHERE 'assets:components:delete' = ANY(permissions);
DELETE FROM permissions WHERE id IN (
    SELECT id FROM (VALUES
        ('assets:components:delete')
    ) AS removed(id)
);
