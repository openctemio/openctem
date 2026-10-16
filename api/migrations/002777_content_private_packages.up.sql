-- Private content packages (RFC-099, docs/architecture/content-catalog.md):
-- an organization (content:publish) or the instance (platform super admin)
-- publishes packages to itself only. A package of a pack type links the
-- content pack its artifact became.
--
-- Safe on populated tables: two nullable columns on a table this release
-- created, plus additive seed rows.
-- expand-contract-ok: the only NOT NULL text is inside a CHECK expression; both columns are nullable.

ALTER TABLE content_packages
    ADD COLUMN content_pack_id uuid,
    ADD COLUMN platform_pack_id uuid REFERENCES platform_content_packs(id) ON DELETE RESTRICT,
    -- The pack of an organization package belongs to the same organization.
    ADD CONSTRAINT fk_content_packages_content_pack FOREIGN KEY (tenant_id, content_pack_id)
        REFERENCES content_packs (tenant_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT chk_content_packages_pack_scope CHECK (
        (content_pack_id IS NULL OR tenant_id IS NOT NULL) AND (platform_pack_id IS NULL OR tenant_id IS NULL));

INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('content:publish', 'settings', 'Publish Private Content', 'Publish and revoke the organization''s private content packages', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'content:publish'
FROM (VALUES ('00000000-0000-0000-0000-000000000001'::uuid), ('00000000-0000-0000-0000-000000000002'::uuid)) AS r(id)
ON CONFLICT (role_id, permission_id) DO NOTHING;
