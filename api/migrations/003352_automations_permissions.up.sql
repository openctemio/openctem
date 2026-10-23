-- Automation permissions (RFC-125 D7). findings:workflows:read and
-- findings:workflows:write become automations:read and automations:write,
-- one to one, in role grants, role-template snapshots and API key
-- scopes (no aliases: minimal back-compat). The new
-- automations:publish (go live, approve another person's version, roll back,
-- change mode, switch on or off, delete) goes to every role that holds
-- automations:write after the rename, so nobody loses a power they had: the
-- go-live gate adds step-up and a second approver on top. Roles created from
-- the security-analyst and vulnerability-manager templates move to template
-- version 3, whose only change is this rename.
--
-- expand-contract-ok: one-step rename; the api that checks the new ids ships in the same release (stop the old api before migrating)

CREATE TEMP TABLE permission_renames_003352 (old_id VARCHAR(100) PRIMARY KEY, new_id VARCHAR(100) NOT NULL, name VARCHAR(100) NOT NULL, description TEXT NOT NULL);
INSERT INTO permission_renames_003352 (old_id, new_id, name, description) VALUES
    ('findings:workflows:read', 'automations:read', 'View Automations', 'View automations, their versions, runs and trace'),
    ('findings:workflows:write', 'automations:write', 'Edit Automations', 'Edit automation drafts, preview, validate and start manual runs');

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT r.new_id, 'workflows', r.name, r.description, true, now()
  FROM permission_renames_003352 r
ON CONFLICT (id) DO NOTHING;
INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
VALUES
    ('automations:publish', 'workflows', 'Publish Automations',
        'Make an automation live (with step-up, and a second publisher for high-risk rules), approve versions, roll back, change mode, switch on or off and delete automations',
        true, now())
ON CONFLICT (id) DO NOTHING;

UPDATE role_permissions rp SET permission_id = r.new_id
  FROM permission_renames_003352 r
 WHERE rp.permission_id = r.old_id
   AND NOT EXISTS (SELECT 1 FROM role_permissions x WHERE x.role_id = rp.role_id AND x.permission_id = r.new_id);
DELETE FROM role_permissions WHERE permission_id IN (SELECT old_id FROM permission_renames_003352);

UPDATE api_keys k SET scopes = array_replace(k.scopes, r.old_id, r.new_id)
  FROM permission_renames_003352 r WHERE r.old_id = ANY(k.scopes);
UPDATE roles ro SET template_permissions = array_replace(ro.template_permissions, r.old_id, r.new_id)
  FROM permission_renames_003352 r WHERE r.old_id = ANY(ro.template_permissions);
UPDATE roles SET template_version = 3
 WHERE template_id IN ('security-analyst', 'vulnerability-manager') AND template_version = 2;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'automations:publish' FROM role_permissions rp WHERE rp.permission_id = 'automations:write'
ON CONFLICT (role_id, permission_id) DO NOTHING;
UPDATE api_keys SET scopes = array_append(scopes, 'automations:publish')
 WHERE 'automations:write' = ANY(scopes) AND NOT ('automations:publish' = ANY(scopes));

DELETE FROM permissions WHERE id IN (SELECT old_id FROM permission_renames_003352);
DROP TABLE permission_renames_003352;
