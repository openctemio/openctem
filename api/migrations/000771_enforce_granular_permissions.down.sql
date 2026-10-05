-- Remove exactly the role grants the up migration added.
DELETE FROM role_permissions rp
USING granular_permission_backfill b
WHERE rp.role_id = b.role_id AND rp.permission_id = b.permission_id;

DROP TABLE IF EXISTS granular_permission_backfill;
