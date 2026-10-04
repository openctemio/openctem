-- Remove permissions that gate nothing and cannot (backlog D-4).
-- (assets:export and findings:export stay: RFC-048 adds server-side exports.)
--   compliance:frameworks:write          frameworks are a read-only seeded
--                                        catalog; no API writes them
--   compliance:reports:read              no compliance report API; the page is
--                                        a redirect
--   findings:policies:*                  the policies module was retired
--                                        (000215) without ever having routes
--   settings:billing:*                   no billing API or page
--
-- The catalog rows and their role grants are copied, as JSON, into
-- access_control_removed_archive first; the down migration restores them.

CREATE TEMP TABLE IF NOT EXISTS meaningless_permission_ids (id VARCHAR(100) PRIMARY KEY);
INSERT INTO meaningless_permission_ids (id) VALUES
    ('compliance:frameworks:write'),
    ('compliance:reports:read'),
    ('findings:policies:read'),
    ('findings:policies:write'),
    ('findings:policies:delete'),
    ('settings:billing:read'),
    ('settings:billing:write')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS access_control_removed_archive (
    id           BIGSERIAL PRIMARY KEY,
    source_table TEXT        NOT NULL,
    row_data     JSONB       NOT NULL,
    archived_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'permissions:000672', to_jsonb(t) FROM permissions t
WHERE t.id IN (SELECT id FROM meaningless_permission_ids);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'role_permissions:000672', to_jsonb(t) FROM role_permissions t
WHERE t.permission_id IN (SELECT id FROM meaningless_permission_ids);

-- role_permissions rows go with the catalog rows (ON DELETE CASCADE).
DELETE FROM permissions WHERE id IN (SELECT id FROM meaningless_permission_ids);
