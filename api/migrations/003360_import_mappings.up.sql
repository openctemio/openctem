-- Tenant import mappings (docs/rfcs/RFC-126-import-mappings.md): a declarative
-- mapping (openctem.io/mapping/v1) that turns a CSV, JSON, JSON Lines or XML
-- export into CTIS. A mapping's content lives in immutable, numbered versions;
-- an import names the version it ran (receipt format "mapping:<name>@<n>").
--
-- Live impact: two new, empty tables.

CREATE TABLE IF NOT EXISTS import_mappings (
    id              uuid          NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid          NOT NULL,
    name            varchar(64)   NOT NULL,
    description     varchar(1000) NOT NULL DEFAULT '',
    source          varchar(8)    NOT NULL,
    latest_version  integer       NOT NULL DEFAULT 1,
    created_by      uuid,
    created_at      timestamptz   NOT NULL DEFAULT now(),
    updated_at      timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT pk_import_mappings PRIMARY KEY (id),
    CONSTRAINT uq_import_mappings_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_import_mappings_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_import_mappings_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_import_mappings_name CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CONSTRAINT chk_import_mappings_source CHECK (source IN ('csv', 'json', 'jsonl', 'xml')),
    CONSTRAINT chk_import_mappings_latest CHECK (latest_version > 0)
);

COMMENT ON TABLE import_mappings IS
    'Declarative mappings an organization defined to import CSV, JSON or XML exports as CTIS.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_import_mappings_name
    ON import_mappings (tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_import_mappings_created_by
    ON import_mappings (created_by) WHERE created_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS import_mapping_versions (
    mapping_id        uuid          NOT NULL,
    tenant_id         uuid          NOT NULL,
    version           integer       NOT NULL,
    document          jsonb         NOT NULL,
    digest            varchar(71)   NOT NULL,
    identity          text[]        NOT NULL DEFAULT '{}',
    identity_changed  boolean       NOT NULL DEFAULT false,
    note              varchar(500)  NOT NULL DEFAULT '',
    created_by        uuid,
    created_at        timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT pk_import_mapping_versions PRIMARY KEY (mapping_id, version),
    -- The version belongs to a mapping of the same organization.
    CONSTRAINT fk_import_mapping_versions_mapping FOREIGN KEY (tenant_id, mapping_id)
        REFERENCES import_mappings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_import_mapping_versions_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_import_mapping_versions_version CHECK (version > 0),
    CONSTRAINT chk_import_mapping_versions_document_size CHECK (pg_column_size(document) <= 262144)
);

COMMENT ON TABLE import_mapping_versions IS
    'Immutable versions of an import mapping; identity_changed marks a version whose identity differs from the previous one.';

CREATE INDEX IF NOT EXISTS idx_import_mapping_versions_tenant
    ON import_mapping_versions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_import_mapping_versions_created_by
    ON import_mapping_versions (created_by) WHERE created_by IS NOT NULL;

-- Policies in shadow mode, like the other tenant tables (row security stays off).
DROP POLICY IF EXISTS import_mappings_tenant_isolation ON import_mappings;
CREATE POLICY import_mappings_tenant_isolation ON import_mappings
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
DROP POLICY IF EXISTS import_mapping_versions_tenant_isolation ON import_mapping_versions;
CREATE POLICY import_mapping_versions_tenant_isolation ON import_mapping_versions
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
