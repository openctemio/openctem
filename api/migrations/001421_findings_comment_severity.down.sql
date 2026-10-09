-- The routes go back to findings:write, which every holder of the two split
-- permissions still has from before the up.
DELETE FROM granular_permission_backfill
WHERE permission_id IN ('findings:comment', 'findings:severity');
DELETE FROM role_permissions WHERE permission_id IN ('findings:comment', 'findings:severity');
DELETE FROM permissions WHERE id IN ('findings:comment', 'findings:severity');
