DELETE FROM role_permissions WHERE permission_id = 'content:publish';
DELETE FROM permissions WHERE id = 'content:publish';

-- Private packages cannot be represented without their pack link.
DELETE FROM content_installs i USING content_packages p
    WHERE i.package_row_id = p.id AND p.origin IN ('organization', 'instance');
DELETE FROM content_install_requests q USING content_packages p
    WHERE q.target_row_id = p.id AND p.origin IN ('organization', 'instance');
UPDATE content_installs SET previous_row_id = NULL
    WHERE previous_row_id IN (SELECT id FROM content_packages WHERE origin IN ('organization', 'instance'));
DELETE FROM content_packages WHERE origin IN ('organization', 'instance');

ALTER TABLE content_packages
    DROP CONSTRAINT IF EXISTS chk_content_packages_pack_scope,
    DROP COLUMN IF EXISTS platform_pack_id,
    DROP COLUMN IF EXISTS content_pack_id;
