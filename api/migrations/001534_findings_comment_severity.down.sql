-- The routes go back to findings:write, which every holder of the two split
-- permissions still has from before the up.
DELETE FROM role_permissions WHERE permission_id IN ('findings:comment', 'findings:severity');
DELETE FROM permissions WHERE id IN ('findings:comment', 'findings:severity');
