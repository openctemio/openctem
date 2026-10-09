-- findings:write gated every change to a finding, including its severity and
-- classification. Whoever could comment on a finding or mark remediation steps
-- could also re-score it. Two actions get their own permission:
--   findings:comment   comments and reactions on a finding
--   findings:severity  severity and classification changes
-- Every role (built-in or custom) that holds findings:write gets both, so no
-- one loses an ability today. Administrators can then remove
-- findings:severity from a custom role (for example a remediation owner).
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('findings:comment', 'findings', 'Comment on Findings', 'Add, edit and delete comments on findings and react to comments', true),
    ('findings:severity', 'findings', 'Change Finding Severity', 'Change the severity and classification of findings', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, p.id
FROM role_permissions rp
CROSS JOIN (VALUES ('findings:comment'), ('findings:severity')) AS p(id)
WHERE rp.permission_id = 'findings:write'
ON CONFLICT (role_id, permission_id) DO NOTHING;
