-- findings:credentials:reveal — returns a leaked credential's plaintext secret.
--
-- findings:credentials:read (held by every system role, viewer included) now
-- returns only a masked value and a keyed fingerprint. Revealing the secret is
-- a separate, audited action that only owners and admins hold by default.
-- Custom roles do not get it; a tenant grants it deliberately.
INSERT INTO permissions (id, module_id, name, description) VALUES
    ('findings:credentials:reveal', 'credentials', 'Reveal Credential Secrets', 'Reveal the plaintext secret of a leaked credential (audited)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'findings:credentials:reveal'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid), -- owner
    ('00000000-0000-0000-0000-000000000002'::uuid)  -- admin
) AS r(role_id)
ON CONFLICT DO NOTHING;
