-- Permissions that were defined but never checked are now enforced on their
-- routes (backlog D-4). Each newly enforced permission P is required IN
-- ADDITION to the permission that already gated the route (RequireAll), so no
-- role gains anything. To keep every role's abilities exactly as they were, P
-- is granted to every role (system and custom) that holds the permission that
-- already gated the route. Owners and administrators can then take P away from
-- a custom role to deny that one action.
--
-- The grants made here are recorded in granular_permission_backfill so the
-- down migration removes exactly them.
--
-- Rows are (n, gate, granted): every role holding `gate` also gets `granted`.
-- n is only an ordinal.

CREATE TEMP TABLE granular_grant_pairs (n INT, gate VARCHAR(100), granted VARCHAR(100));
INSERT INTO granular_grant_pairs (n, gate, granted) VALUES
    (1,  'assets:write',             'assets:import'),
    (2,  'findings:read',            'ai_triage:read'),
    (3,  'findings:write',           'ai_triage:trigger'),
    (4,  'findings:read',            'findings:exposures:read'),
    (5,  'findings:write',           'findings:exposures:write'),
    (6,  'findings:write',           'findings:exposures:triage'),
    (7,  'findings:approve',         'findings:exposures:triage'),
    (8,  'findings:delete',          'findings:exposures:delete'),
    (9,  'integrations:pipelines:write', 'integrations:pipelines:execute'),
    (10, 'integrations:read',        'integrations:scm:read'),
    (11, 'integrations:manage',      'integrations:scm:write'),
    (12, 'integrations:manage',      'integrations:scm:delete'),
    (13, 'scans:write',              'scans:execute'),
    (14, 'assets:write',             'scans:execute'),
    (15, 'team:groups:write',        'team:groups:assets');

CREATE TABLE IF NOT EXISTS granular_permission_backfill (
    role_id       UUID         NOT NULL,
    permission_id VARCHAR(100) NOT NULL,
    PRIMARY KEY (role_id, permission_id)
);
COMMENT ON TABLE granular_permission_backfill IS
    'Role grants added by migration 000467; its down migration removes exactly these';

WITH ins AS (
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT DISTINCT rp.role_id, g.granted
    FROM role_permissions rp
    JOIN granular_grant_pairs g ON g.gate = rp.permission_id
    WHERE EXISTS (SELECT 1 FROM permissions p WHERE p.id = g.granted)
    ON CONFLICT (role_id, permission_id) DO NOTHING
    RETURNING role_id, permission_id
)
INSERT INTO granular_permission_backfill (role_id, permission_id)
SELECT role_id, permission_id FROM ins
ON CONFLICT DO NOTHING;

-- Any member could read their organization, its members and its settings
-- (GET /api/v1/tenants/{tenant}, /members, /invitations, /settings); those
-- reads now need team:read, team:members:read and settings:read. The system
-- roles already hold them; grant them to every custom role so no member loses
-- a read.
WITH ins AS (
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id
    FROM roles r
    CROSS JOIN (VALUES ('team:read'), ('team:members:read'), ('settings:read')) AS p(id)
    WHERE r.tenant_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM permissions x WHERE x.id = p.id)
    ON CONFLICT (role_id, permission_id) DO NOTHING
    RETURNING role_id, permission_id
)
INSERT INTO granular_permission_backfill (role_id, permission_id)
SELECT role_id, permission_id FROM ins
ON CONFLICT DO NOTHING;

DROP TABLE granular_grant_pairs;
