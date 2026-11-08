DELETE FROM role_permissions WHERE permission_id = 'findings:sources:retire';
DELETE FROM permissions WHERE id = 'findings:sources:retire';
DROP TABLE IF EXISTS source_retirement_findings;
DROP TABLE IF EXISTS source_retirements;
DROP FUNCTION IF EXISTS source_retirement_matches(text, uuid, text, text, text, uuid, text, text);
