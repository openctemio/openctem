-- scans:freeze:override becomes scans:windows:override (RFC-067 §8): the
-- emergency override of scan window policies, which needs a fresh
-- authenticator code and a reason. Every role and API key that held the old
-- permission holds the new one; nothing else changes hands.

CREATE TEMP TABLE IF NOT EXISTS permission_renames_001631 (old_id VARCHAR(100) PRIMARY KEY, new_id VARCHAR(100) NOT NULL, name VARCHAR(100) NOT NULL, description TEXT NOT NULL);
INSERT INTO permission_renames_001631 (old_id, new_id, name, description) VALUES
    ('scans:freeze:override', 'scans:windows:override', 'Override Scan Windows', 'Suspend scan window policies for up to 24 hours with an authenticator code and a reason (audited); program windows cannot be overridden')
ON CONFLICT DO NOTHING;

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT r.new_id, p.module_id, r.name, r.description, p.is_active, p.created_at
FROM permission_renames_001631 r JOIN permissions p ON p.id = r.old_id
ON CONFLICT (id) DO NOTHING;

UPDATE role_permissions rp SET permission_id = r.new_id
FROM permission_renames_001631 r WHERE rp.permission_id = r.old_id;
UPDATE api_keys k SET scopes = array_replace(k.scopes, r.old_id, r.new_id)
FROM permission_renames_001631 r WHERE r.old_id = ANY(k.scopes);
DELETE FROM permissions WHERE id IN (SELECT old_id FROM permission_renames_001631);

DROP TABLE permission_renames_001631;
