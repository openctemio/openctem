-- Ticket field mapping profiles (docs/rfcs/RFC-097-ticket-field-mapping.md):
-- which OpenCTEM attribute maps to which tracker field and status, per
-- integration, destination project and issue type, and object kind (finding
-- or remediation task).
--
-- A profile's content lives in versions: at most one open draft, at most one
-- published version, older published versions superseded. Publishing and
-- rolling back never rewrite a published row; a rollback copies an old spec
-- into a new draft. The snapshot keeps the tracker metadata a version was
-- checked against, for drift detection.
--
-- Live impact: two new, empty tables.

CREATE TABLE IF NOT EXISTS ticket_mapping_profiles (
    id                 uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id          uuid         NOT NULL,
    integration_id     uuid         NOT NULL,
    object_kind        varchar(16)  NOT NULL,
    project_id         varchar(64)  NOT NULL DEFAULT '',
    project_key        varchar(32)  NOT NULL,
    issue_type_id      varchar(64)  NOT NULL,
    issue_type         varchar(128) NOT NULL DEFAULT '',
    name               varchar(120) NOT NULL,
    published_version  integer      NOT NULL DEFAULT 0,
    draft_version      integer      NOT NULL DEFAULT 0,
    dry_run            boolean      NOT NULL DEFAULT false,
    drifted            boolean      NOT NULL DEFAULT false,
    created_by         uuid,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ticket_mapping_profiles PRIMARY KEY (id),
    CONSTRAINT fk_ticket_mapping_profiles_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    -- The integration must belong to the profile's own organization.
    CONSTRAINT fk_ticket_mapping_profiles_integration_tenant FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_mapping_profiles_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_ticket_mapping_profiles_kind CHECK (object_kind IN ('finding', 'task')),
    CONSTRAINT chk_ticket_mapping_profiles_versions CHECK (published_version >= 0 AND draft_version >= 0)
);

COMMENT ON TABLE ticket_mapping_profiles IS
    'Field and status mapping between OpenCTEM objects and one tracker destination (integration, project, issue type).';

CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_mapping_profiles_destination
    ON ticket_mapping_profiles (tenant_id, integration_id, object_kind, project_key, issue_type_id);
CREATE INDEX IF NOT EXISTS idx_ticket_mapping_profiles_created_by
    ON ticket_mapping_profiles (created_by) WHERE created_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS ticket_mapping_versions (
    profile_id    uuid         NOT NULL,
    tenant_id     uuid         NOT NULL,
    version       integer      NOT NULL,
    state         varchar(16)  NOT NULL,
    spec          jsonb        NOT NULL,
    snapshot      jsonb,
    note          varchar(500) NOT NULL DEFAULT '',
    created_by    uuid,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    published_by  uuid,
    published_at  timestamptz,
    CONSTRAINT pk_ticket_mapping_versions PRIMARY KEY (profile_id, version),
    CONSTRAINT fk_ticket_mapping_versions_profile FOREIGN KEY (profile_id)
        REFERENCES ticket_mapping_profiles (id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_mapping_versions_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_mapping_versions_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_ticket_mapping_versions_published_by FOREIGN KEY (published_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_ticket_mapping_versions_state CHECK (state IN ('draft', 'published', 'superseded')),
    CONSTRAINT chk_ticket_mapping_versions_version CHECK (version > 0),
    CONSTRAINT chk_ticket_mapping_versions_spec_size CHECK (pg_column_size(spec) <= 262144)
);

COMMENT ON TABLE ticket_mapping_versions IS
    'Versions of a ticket mapping profile: one open draft, one published, the rest superseded.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_mapping_versions_one_draft
    ON ticket_mapping_versions (profile_id) WHERE state = 'draft';
CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_mapping_versions_one_published
    ON ticket_mapping_versions (profile_id) WHERE state = 'published';
CREATE INDEX IF NOT EXISTS idx_ticket_mapping_versions_tenant
    ON ticket_mapping_versions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_ticket_mapping_versions_created_by
    ON ticket_mapping_versions (created_by) WHERE created_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_mapping_versions_published_by
    ON ticket_mapping_versions (published_by) WHERE published_by IS NOT NULL;

-- Policies in shadow mode, like the other tenant tables (row security stays off).
DROP POLICY IF EXISTS ticket_mapping_profiles_tenant_isolation ON ticket_mapping_profiles;
CREATE POLICY ticket_mapping_profiles_tenant_isolation ON ticket_mapping_profiles
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
DROP POLICY IF EXISTS ticket_mapping_versions_tenant_isolation ON ticket_mapping_versions;
CREATE POLICY ticket_mapping_versions_tenant_isolation ON ticket_mapping_versions
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
