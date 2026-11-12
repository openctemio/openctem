-- Repair: re-applies, idempotently, three migrations that databases upgraded
-- across them never ran. golang-migrate only runs versions above a database's
-- current one, and these were merged below versions already applied:
--   002571_content_catalog
--   002817_verified_domain_signup_policy
--   002830_organization_join_requests
-- Every statement is a no-op where the object already exists (fresh installs,
-- databases that ran the originals) and completes the schema where it does
-- not. Definitions are copied from the originals.
--
-- Safe on populated tables: new tables, additive columns with constant
-- defaults, additive seed rows.

-- ---------------------------------------------------------------- 002571
-- One row per instance: the applied signed state (no rollback below it).
CREATE TABLE IF NOT EXISTS content_catalog_trust (
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
CREATE TABLE IF NOT EXISTS content_packages (
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

CREATE UNIQUE INDEX IF NOT EXISTS uq_content_packages_instance ON content_packages (package_id, version) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_content_packages_organization ON content_packages (tenant_id, package_id, version) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_content_packages_artifact ON content_packages (artifact_digest);

-- The applied revocation entries. Kept: an older bundle can never bring a
-- revoked package back.
CREATE TABLE IF NOT EXISTS content_revocations (
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

CREATE UNIQUE INDEX IF NOT EXISTS uq_content_revocations_entry
    ON content_revocations (COALESCE(package_id, ''), COALESCE(version, ''), COALESCE(digest, ''));

-- What each organization installed.
CREATE TABLE IF NOT EXISTS content_installs (
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

CREATE INDEX IF NOT EXISTS idx_content_installs_row ON content_installs (package_row_id);

-- Install, update, rollback and uninstall requests when the organization
-- wants a second person to approve them.
CREATE TABLE IF NOT EXISTS content_install_requests (
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

CREATE UNIQUE INDEX IF NOT EXISTS uq_content_install_requests_pending ON content_install_requests (tenant_id, package_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_content_install_requests_tenant ON content_install_requests (tenant_id, created_at DESC);

-- The approval option per organization (no row: off).
CREATE TABLE IF NOT EXISTS content_catalog_settings (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    require_approval boolean NOT NULL DEFAULT false,
    -- Turning approval off takes effect at this time (24 hours later), so a
    -- stolen session cannot switch four eyes off unnoticed.
    approval_off_at  timestamptz,
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

-- ---------------------------------------------------------------- 002817
ALTER TABLE verified_domains
    ADD COLUMN IF NOT EXISTS join_policy text NOT NULL DEFAULT 'off',
    ADD COLUMN IF NOT EXISTS join_role text NOT NULL DEFAULT 'viewer',
    ADD COLUMN IF NOT EXISTS discoverable boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS sso_required boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS block_new_workspaces boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS include_subdomains boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS capture_notified_at timestamp with time zone;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_verified_domains_join_policy'
                     AND conrelid = 'verified_domains'::regclass) THEN
        ALTER TABLE verified_domains ADD CONSTRAINT chk_verified_domains_join_policy
            CHECK (join_policy IN ('off', 'approval', 'auto'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_verified_domains_join_role'
                     AND conrelid = 'verified_domains'::regclass) THEN
        ALTER TABLE verified_domains ADD CONSTRAINT chk_verified_domains_join_role
            CHECK (join_role IN ('viewer', 'member'));
    END IF;
END $$;

-- ---------------------------------------------------------------- 002830
CREATE TABLE IF NOT EXISTS organization_join_requests (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain_id uuid REFERENCES verified_domains(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'pending',
    requested_role text NOT NULL DEFAULT 'viewer',
    decided_role text,
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_join_requests_status CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT chk_join_requests_role CHECK (requested_role IN ('viewer', 'member')
        AND (decided_role IS NULL OR decided_role IN ('viewer', 'member')))
);

-- One pending request per person and organization.
CREATE UNIQUE INDEX IF NOT EXISTS uq_join_requests_pending ON organization_join_requests (tenant_id, user_id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_join_requests_tenant_status ON organization_join_requests (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_join_requests_user ON organization_join_requests (user_id, created_at DESC);
