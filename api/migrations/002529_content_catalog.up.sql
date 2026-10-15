-- Content catalog (RFC-099, docs/architecture/content-catalog.md).
--
-- What the instance holds (verified content packages), the signed state it
-- applied (key set version, index and revocation list sequences), the
-- revocations it applied, what each organization installed, the approval
-- requests and the approval setting. Permissions content:read and
-- content:install.
--
-- Safe on populated tables: new tables only, plus additive seed rows.

-- One row per instance: the applied signed state (no rollback below it).
CREATE TABLE content_catalog_trust (
    id                     smallint PRIMARY KEY DEFAULT 1,
    keyset_version         bigint NOT NULL DEFAULT 0,
    index_sequence         bigint NOT NULL DEFAULT 0,
    index_digest           varchar(71),
    index_expires_at       timestamptz,
    revocations_sequence   bigint NOT NULL DEFAULT 0,
    revocations_digest     varchar(71),
    revocations_issued_at  timestamptz,
    revocations_expires_at timestamptz,
    imported_at            timestamptz,
    CONSTRAINT chk_content_catalog_trust_single CHECK (id = 1),
    CONSTRAINT chk_content_catalog_trust_counters CHECK (keyset_version >= 0 AND index_sequence >= 0 AND revocations_sequence >= 0)
);

-- Package versions. tenant_id NULL: the instance catalog (signed bundles,
-- instance publishing); set: one organization's private package.
CREATE TABLE content_packages (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid REFERENCES tenants(id) ON DELETE CASCADE,
    package_id          varchar(81) NOT NULL,
    version             varchar(64) NOT NULL,
    type                varchar(32) NOT NULL,
    origin              varchar(16) NOT NULL,
    title               varchar(80) NOT NULL,
    manifest            jsonb NOT NULL,
    manifest_raw        bytea NOT NULL,
    manifest_digest     varchar(71) NOT NULL,
    artifact_media_type varchar(64) NOT NULL,
    artifact_digest     varchar(71) NOT NULL,
    artifact_size       bigint NOT NULL,
    statement           bytea NOT NULL,
    publisher_signature bytea,
    publisher_identity  text,
    publisher_issuer    text,
    publisher_signed_at timestamptz,
    tier                varchar(2) NOT NULL,
    service_use         boolean NOT NULL,
    revoked_at          timestamptz,
    revoke_reason       text,
    revoke_severity     varchar(16),
    created_by          uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_content_packages_type CHECK (type IN ('rules', 'templates', 'wordlists', 'profiles',
        'report-templates', 'playbooks', 'policy-packs', 'tool-adapters', 'sensors', 'feeds')),
    CONSTRAINT chk_content_packages_origin CHECK (
        (tenant_id IS NULL AND origin IN ('first-party', 'catalog', 'instance'))
        OR (tenant_id IS NOT NULL AND origin = 'organization')),
    CONSTRAINT chk_content_packages_tier CHECK (tier IN ('T0', 'T1', 'T2')),
    CONSTRAINT chk_content_packages_digests CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$' AND artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT chk_content_packages_revoked CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE UNIQUE INDEX uq_content_packages_instance ON content_packages (package_id, version) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX uq_content_packages_organization ON content_packages (tenant_id, package_id, version) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_content_packages_artifact ON content_packages (artifact_digest);

-- The applied revocation entries. Kept: an older bundle can never bring a
-- revoked package back.
CREATE TABLE content_revocations (
    id            bigserial PRIMARY KEY,
    package_id    varchar(81),
    version       varchar(64),
    digest        varchar(71),
    reason        text NOT NULL,
    severity      varchar(16) NOT NULL,
    revoked_at    timestamptz NOT NULL,
    list_sequence bigint NOT NULL,
    CONSTRAINT chk_content_revocations_target CHECK (
        (digest IS NOT NULL AND package_id IS NULL AND version IS NULL)
        OR (digest IS NULL AND package_id IS NOT NULL)),
    CONSTRAINT chk_content_revocations_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE UNIQUE INDEX uq_content_revocations_entry
    ON content_revocations (COALESCE(package_id, ''), COALESCE(version, ''), COALESCE(digest, ''));

-- What each organization installed.
CREATE TABLE content_installs (
    id                   uuid PRIMARY KEY,
    tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    package_id           varchar(81) NOT NULL,
    package_row_id       uuid NOT NULL REFERENCES content_packages(id) ON DELETE RESTRICT,
    previous_row_id      uuid REFERENCES content_packages(id) ON DELETE SET NULL,
    pinned               boolean NOT NULL DEFAULT false,
    status               varchar(16) NOT NULL DEFAULT 'active',
    license_acknowledged boolean NOT NULL DEFAULT false,
    installed_by         uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_content_installs_package UNIQUE (tenant_id, package_id),
    CONSTRAINT chk_content_installs_status CHECK (status IN ('active', 'revoked'))
);

CREATE INDEX idx_content_installs_row ON content_installs (package_row_id);

-- Install, update, rollback and uninstall requests when the organization
-- wants a second person to approve them.
CREATE TABLE content_install_requests (
    id                   uuid PRIMARY KEY,
    tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    package_id           varchar(81) NOT NULL,
    action               varchar(16) NOT NULL,
    target_row_id        uuid REFERENCES content_packages(id) ON DELETE CASCADE,
    pinned               boolean NOT NULL DEFAULT false,
    license_acknowledged boolean NOT NULL DEFAULT false,
    status               varchar(16) NOT NULL DEFAULT 'pending',
    note                 text NOT NULL DEFAULT '',
    decision_reason      text NOT NULL DEFAULT '',
    requested_by         uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at           timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_content_install_requests_action CHECK (action IN ('install', 'update', 'rollback', 'uninstall')),
    CONSTRAINT chk_content_install_requests_target CHECK ((action = 'uninstall') = (target_row_id IS NULL)),
    CONSTRAINT chk_content_install_requests_status CHECK (status IN ('pending', 'approved', 'rejected', 'canceled', 'failed')),
    CONSTRAINT chk_content_install_requests_four_eyes CHECK (decided_by IS NULL OR requested_by IS NULL OR decided_by <> requested_by),
    CONSTRAINT chk_content_install_requests_text CHECK (char_length(note) <= 500 AND char_length(decision_reason) <= 500)
);

CREATE UNIQUE INDEX uq_content_install_requests_pending ON content_install_requests (tenant_id, package_id) WHERE status = 'pending';
CREATE INDEX idx_content_install_requests_tenant ON content_install_requests (tenant_id, created_at DESC);

-- The approval option per organization (no row: off).
CREATE TABLE content_catalog_settings (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    require_approval boolean NOT NULL DEFAULT false,
    updated_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('content:read', 'settings', 'View Content Catalog', 'Browse the content catalog, installed packages and the trust status', true),
    ('content:install', 'settings', 'Install Content', 'Install, update, pin, roll back and uninstall content packages; approve or reject the requests of others', true)
ON CONFLICT (id) DO NOTHING;

-- Owner and admin: both; member and viewer: read.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM (VALUES ('00000000-0000-0000-0000-000000000001'::uuid), ('00000000-0000-0000-0000-000000000002'::uuid)) AS r(id)
CROSS JOIN (VALUES ('content:read'), ('content:install')) AS p(id)
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'content:read'
FROM (VALUES ('00000000-0000-0000-0000-000000000003'::uuid), ('00000000-0000-0000-0000-000000000004'::uuid)) AS r(id)
ON CONFLICT (role_id, permission_id) DO NOTHING;
