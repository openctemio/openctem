-- Content packs (api/docs/rfcs/RFC-061-content-packs.md): immutable,
-- content-addressed packs of templates, rules, wordlists and other tool
-- content, linted, classified and signed by the platform.
--
-- content_pack_blobs: one canonical archive per (tenant, digest), stored in
-- the tenant's namespace of the operator file storage. Never shared across
-- tenants: the same bytes uploaded by two tenants are two blobs, so a digest
-- lookup cannot reveal what another tenant holds.
-- content_packs: a named, versioned pack over one blob. Immutable except
-- revocation.

CREATE TABLE content_pack_blobs (
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    digest      varchar(71) NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes  bigint NOT NULL CHECK (size_bytes > 0),
    file_count  integer NOT NULL CHECK (file_count > 0),
    storage_key varchar(512) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, digest)
);

COMMENT ON TABLE content_pack_blobs IS
    'Canonical content pack archives (RFC-061), content-addressed per tenant. Untrusted content.';

CREATE TABLE content_packs (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          varchar(64) NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    version       varchar(64) NOT NULL CHECK (version ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$'),
    kind          varchar(80) NOT NULL CHECK (kind ~ '^([a-z][a-z0-9-]{1,40}|x-[a-z0-9-]{1,32}/[a-z][a-z0-9-]{1,40})$'),
    digest        varchar(71) NOT NULL,
    tier          varchar(2) NOT NULL CHECK (tier IN ('T0', 'T1', 'T2')),
    status        varchar(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    source        varchar(16) NOT NULL CHECK (source IN ('upload', 'git', 'https', 'oci', 's3')),
    source_ref    varchar(1024),
    lint          jsonb NOT NULL DEFAULT '{}'::jsonb,
    signature     jsonb NOT NULL,
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    revoked_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    revoke_reason varchar(500),
    CONSTRAINT fk_content_packs_blob FOREIGN KEY (tenant_id, digest)
        REFERENCES content_pack_blobs (tenant_id, digest) ON DELETE RESTRICT,
    CONSTRAINT uq_content_packs_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_content_packs_tenant_name_version UNIQUE (tenant_id, name, version),
    CONSTRAINT chk_content_packs_lint_size CHECK (pg_column_size(lint) <= 200000),
    CONSTRAINT chk_content_packs_revoked CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

COMMENT ON TABLE content_packs IS
    'Tenant content packs (RFC-061). lint and tier are the platform verdicts; signature is the DSSE statement sensors verify. Never served to another tenant.';

CREATE INDEX idx_content_packs_tenant_created ON content_packs (tenant_id, created_at DESC);
CREATE INDEX idx_content_packs_tenant_digest ON content_packs (tenant_id, digest);

INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('scans:content:read', 'scans', 'View Content Packs', 'View content packs (templates, rules, wordlists), their lint results and archives', true),
    ('scans:content:write', 'scans', 'Manage Content Packs', 'Upload and revoke content packs', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN (VALUES ('scans:content:read'), ('scans:content:write')) AS p(id)
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;
