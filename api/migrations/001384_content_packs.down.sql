DELETE FROM role_permissions WHERE permission_id IN ('scans:content:read', 'scans:content:write');
DELETE FROM permissions WHERE id IN ('scans:content:read', 'scans:content:write');

DROP TABLE IF EXISTS content_packs;
DROP TABLE IF EXISTS content_pack_blobs;
