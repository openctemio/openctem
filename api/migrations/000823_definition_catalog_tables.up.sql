-- Identifiers, relations, taxonomy links and finding links for the definition
-- catalog (RFC-044 §5.2-§5.4, §5.7).
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
--
-- New, empty tables and two NOT VALID constraints: short locks only. The
-- backfill is 000824, validation 000825.
--
-- Tenant isolation is enforced by the schema, not only by the queries:
--
--   * Every reference to a definition is (definition_id, <scope column>) ->
--     vulnerabilities (id, scope_tenant_id), with a CHECK that the scope is
--     the nil UUID (global) or the referencing row's own tenant. A row can
--     therefore name a global definition or one of its own tenant's, never
--     another tenant's. The scope columns are NOT NULL because a foreign key
--     does not check a row whose key has a NULL column.
--   * finding_definitions references its finding by (id, tenant_id), as
--     finding_fingerprints does (000371), so its tenant_id is the finding's.
--   * findings.definition_id must be one of the finding's own links
--     (findings (id, tenant_id, definition_id) -> finding_definitions).
--   * Shared (global) content can only come from trusted sources: a global
--     alias identifier only from osv/ghsa/cve_list, a global relation or
--     taxonomy link only from a feed or the rule-catalog import. A report can
--     never assert one (RFC-044 §5.5, §10 "poisoning the global catalog").

-- A definition merged into another: the target is global or the same tenant's.
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS fk_vulnerabilities_merged_into;
ALTER TABLE vulnerabilities
    ADD CONSTRAINT fk_vulnerabilities_merged_into FOREIGN KEY (merged_into, merged_into_scope)
        REFERENCES vulnerabilities (id, scope_tenant_id) NOT VALID;

-- §5.2: "the same issue". Every identifier resolves to exactly one definition
-- in its scope. This is RFC-043's vulnerability_aliases (decision D7).
CREATE TABLE IF NOT EXISTS definition_identifiers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    namespace       VARCHAR(100) NOT NULL,
    external_id     VARCHAR(512) NOT NULL,
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    scope_tenant_id UUID NOT NULL,
    definition_id   UUID NOT NULL,
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    asserted_by     VARCHAR(20) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_definition_identifiers_definition FOREIGN KEY (definition_id, scope_tenant_id)
        REFERENCES vulnerabilities (id, scope_tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_definition_identifiers_scope CHECK (
        scope_tenant_id = COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT chk_definition_identifiers_namespace CHECK (
        namespace ~ '^[A-Z][A-Z0-9_]{0,31}(:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$'),
    CONSTRAINT chk_definition_identifiers_external_id CHECK (external_id <> ''),
    CONSTRAINT chk_definition_identifiers_asserted_by CHECK (asserted_by IN (
        'cve_list', 'nvd', 'osv', 'ghsa', 'kev', 'rule_catalog', 'report', 'tenant')),
    -- A global alias (not the definition's own primary id) only from the
    -- feeds that publish alias sets; a tenant identifier only from that
    -- tenant's reports or users.
    CONSTRAINT chk_definition_identifiers_trust CHECK (
        (tenant_id IS NULL AND asserted_by <> 'tenant'
         AND (is_primary OR asserted_by IN ('osv', 'ghsa', 'cve_list')))
        OR (tenant_id IS NOT NULL AND asserted_by IN ('report', 'tenant')))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_definition_identifiers_global
    ON definition_identifiers (namespace, external_id) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_definition_identifiers_tenant
    ON definition_identifiers (tenant_id, namespace, external_id) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_definition_identifiers_primary
    ON definition_identifiers (definition_id) WHERE is_primary;
CREATE INDEX IF NOT EXISTS idx_definition_identifiers_definition
    ON definition_identifiers (definition_id);

COMMENT ON TABLE definition_identifiers IS
    'Every identifier of a definition (RFC-044 §5.2; RFC-043 vulnerability_aliases). tenant_id NULL = global identifier.';

-- Every definition owns its primary identifier from the moment it exists,
-- whichever code inserts it (the deployed ingest writes catalog rows without
-- knowing this table exists). Once per statement: a batch insert of 500 CVEs
-- is one INSERT here. Existing rows are backfilled by 000824.
CREATE OR REPLACE FUNCTION vulnerabilities_primary_identifier() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO definition_identifiers
        (namespace, external_id, tenant_id, scope_tenant_id, definition_id, is_primary, asserted_by)
    SELECT n.namespace, n.external_id, n.tenant_id, n.scope_tenant_id, n.id, TRUE, n.origin
    FROM new_definitions n
    WHERE n.external_id IS NOT NULL
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trigger_vulnerabilities_primary_identifier ON vulnerabilities;
CREATE TRIGGER trigger_vulnerabilities_primary_identifier
    AFTER INSERT ON vulnerabilities
    REFERENCING NEW TABLE AS new_definitions
    FOR EACH STATEMENT EXECUTE FUNCTION vulnerabilities_primary_identifier();

-- §5.3: different issues that are connected. upstream (a distro advisory
-- bundles a library CVE), related, detects (a rule/plugin/template detects a
-- vulnerability). tenant_id NULL = a shared edge between global definitions;
-- a tenant edge may connect that tenant's definitions and global ones.
CREATE TABLE IF NOT EXISTS definition_relations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    scope_tenant_id UUID NOT NULL,
    from_id         UUID NOT NULL,
    from_scope      UUID NOT NULL,
    to_id           UUID NOT NULL,
    to_scope        UUID NOT NULL,
    relation        VARCHAR(20) NOT NULL,
    asserted_by     VARCHAR(20) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_definition_relations_from FOREIGN KEY (from_id, from_scope)
        REFERENCES vulnerabilities (id, scope_tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_definition_relations_to FOREIGN KEY (to_id, to_scope)
        REFERENCES vulnerabilities (id, scope_tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_definition_relations_scope CHECK (
        scope_tenant_id = COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
        AND from_scope IN ('00000000-0000-0000-0000-000000000000'::uuid, scope_tenant_id)
        AND to_scope IN ('00000000-0000-0000-0000-000000000000'::uuid, scope_tenant_id)),
    CONSTRAINT chk_definition_relations_not_self CHECK (from_id <> to_id),
    CONSTRAINT chk_definition_relations_relation CHECK (relation IN ('upstream', 'related', 'detects')),
    CONSTRAINT chk_definition_relations_asserted_by CHECK (asserted_by IN (
        'cve_list', 'nvd', 'osv', 'ghsa', 'kev', 'rule_catalog', 'report', 'tenant')),
    CONSTRAINT chk_definition_relations_trust CHECK (
        (tenant_id IS NULL AND asserted_by IN ('cve_list', 'nvd', 'osv', 'ghsa', 'rule_catalog'))
        OR (tenant_id IS NOT NULL AND asserted_by IN ('report', 'tenant')))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_definition_relations_edge
    ON definition_relations (scope_tenant_id, from_id, to_id, relation);
CREATE INDEX IF NOT EXISTS idx_definition_relations_from ON definition_relations (from_id);
CREATE INDEX IF NOT EXISTS idx_definition_relations_to ON definition_relations (to_id);

COMMENT ON TABLE definition_relations IS
    'upstream / related / detects edges between definitions (RFC-044 §5.3). Never aliases.';

-- §5.4: taxonomies (CWE, CAPEC, OWASP, ASVS, ATT&CK, CIS/NIST/ISO controls)
-- classify definitions; they are not definitions. Global, platform-seeded.
CREATE TABLE IF NOT EXISTS taxonomy_entries (
    namespace   VARCHAR(100) NOT NULL,
    external_id VARCHAR(200) NOT NULL,
    title       VARCHAR(500),
    parent_id   VARCHAR(200),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (namespace, external_id),
    CONSTRAINT chk_taxonomy_entries_namespace CHECK (
        namespace ~ '^[A-Z][A-Z0-9_]{0,31}(:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$'),
    CONSTRAINT chk_taxonomy_entries_external_id CHECK (external_id <> '')
);

DROP TRIGGER IF EXISTS trigger_taxonomy_entries_updated_at ON taxonomy_entries;
CREATE TRIGGER trigger_taxonomy_entries_updated_at
    BEFORE UPDATE ON taxonomy_entries
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE taxonomy_entries IS 'Global taxonomy catalog (CWE, CAPEC, OWASP, ...), RFC-044 §5.4.';

-- A definition's taxonomy links. No foreign key to taxonomy_entries: a CWE a
-- feed names is linked before the taxonomy seed lists it.
CREATE TABLE IF NOT EXISTS definition_taxonomy (
    definition_id   UUID NOT NULL,
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    scope_tenant_id UUID NOT NULL,
    namespace       VARCHAR(100) NOT NULL,
    external_id     VARCHAR(200) NOT NULL,
    asserted_by     VARCHAR(20) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (definition_id, namespace, external_id),
    CONSTRAINT fk_definition_taxonomy_definition FOREIGN KEY (definition_id, scope_tenant_id)
        REFERENCES vulnerabilities (id, scope_tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_definition_taxonomy_scope CHECK (
        scope_tenant_id = COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT chk_definition_taxonomy_namespace CHECK (
        namespace ~ '^[A-Z][A-Z0-9_]{0,31}(:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$'),
    CONSTRAINT chk_definition_taxonomy_external_id CHECK (external_id <> ''),
    CONSTRAINT chk_definition_taxonomy_asserted_by CHECK (asserted_by IN (
        'cve_list', 'nvd', 'osv', 'ghsa', 'kev', 'rule_catalog', 'report', 'tenant')),
    -- The reporter's per-instance CWE stays on findings.cwe_ids (§5.4); a
    -- shared mapping only from feeds and the rule catalog.
    CONSTRAINT chk_definition_taxonomy_trust CHECK (
        (tenant_id IS NULL AND asserted_by IN ('cve_list', 'nvd', 'osv', 'ghsa', 'kev', 'rule_catalog'))
        OR (tenant_id IS NOT NULL AND asserted_by IN ('report', 'tenant')))
);

CREATE INDEX IF NOT EXISTS idx_definition_taxonomy_entry ON definition_taxonomy (namespace, external_id);

COMMENT ON TABLE definition_taxonomy IS 'Taxonomy links of a definition (RFC-044 §5.4), in the definition''s scope.';

-- §5.7: findings as instances of definitions. One primary (ord 0), then
-- detected_by / additional / alias / weakness links.
CREATE TABLE IF NOT EXISTS finding_definitions (
    finding_id       UUID NOT NULL,
    tenant_id        UUID NOT NULL,
    definition_id    UUID NOT NULL,
    definition_scope UUID NOT NULL,
    role             VARCHAR(20) NOT NULL,
    ord              SMALLINT NOT NULL,
    asserted_by      VARCHAR(20) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (finding_id, definition_id),
    CONSTRAINT ux_finding_definitions_ord UNIQUE (finding_id, ord),
    CONSTRAINT fk_finding_definitions_finding FOREIGN KEY (finding_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_definitions_definition FOREIGN KEY (definition_id, definition_scope)
        REFERENCES vulnerabilities (id, scope_tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_definitions_scope CHECK (
        definition_scope IN ('00000000-0000-0000-0000-000000000000'::uuid, tenant_id)),
    CONSTRAINT chk_finding_definitions_role CHECK (role IN (
        'primary', 'detected_by', 'additional', 'alias', 'weakness')),
    CONSTRAINT chk_finding_definitions_ord CHECK (ord >= 0 AND (ord = 0) = (role = 'primary')),
    CONSTRAINT chk_finding_definitions_asserted_by CHECK (asserted_by IN ('report', 'feed', 'user'))
);

-- Target of findings.definition_id's foreign key below.
CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_definitions_finding_tenant_definition
    ON finding_definitions (finding_id, tenant_id, definition_id);
-- The Issues rollup: findings per definition in one tenant (RFC-044 §7).
CREATE INDEX IF NOT EXISTS idx_finding_definitions_tenant_definition
    ON finding_definitions (tenant_id, definition_id);
CREATE INDEX IF NOT EXISTS idx_finding_definitions_definition
    ON finding_definitions (definition_id);

COMMENT ON TABLE finding_definitions IS
    'Links a finding to its definitions (RFC-044 §5.7): role primary at ord 0, then detected_by/additional/alias/weakness.';

-- findings.definition_id: the primary definition, denormalized for hot paths.
-- It must be one of the finding's own links, which already proves the
-- definition is global or the finding's tenant's. Deferred, so a transaction
-- can replace a finding's links and its primary in any order. NOT VALID here
-- (no scan under this migration's lock); 000825 validates.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS definition_id UUID;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_definition_link;
ALTER TABLE findings
    ADD CONSTRAINT fk_findings_definition_link FOREIGN KEY (id, tenant_id, definition_id)
        REFERENCES finding_definitions (finding_id, tenant_id, definition_id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

-- Deleting a definition clears the pointer in the same statement that
-- cascades its links away (as findings.vulnerability_id does).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_definition;
ALTER TABLE findings
    ADD CONSTRAINT fk_findings_definition FOREIGN KEY (definition_id)
        REFERENCES vulnerabilities (id) ON DELETE SET NULL NOT VALID;

COMMENT ON COLUMN findings.definition_id IS
    'Primary definition (RFC-044 §5.7), denormalized from finding_definitions ord 0.';

-- RLS shadow policies (not enabled; see migration 000157).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'finding_definitions'
                   AND policyname = 'finding_definitions_tenant_isolation') THEN
        CREATE POLICY finding_definitions_tenant_isolation ON finding_definitions
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                   OR current_setting('app.is_platform_admin', true) = 'true');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'definition_identifiers'
                   AND policyname = 'definition_identifiers_scope_isolation') THEN
        CREATE POLICY definition_identifiers_scope_isolation ON definition_identifiers
            USING (tenant_id IS NULL
                   OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                   OR current_setting('app.is_platform_admin', true) = 'true');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'definition_relations'
                   AND policyname = 'definition_relations_scope_isolation') THEN
        CREATE POLICY definition_relations_scope_isolation ON definition_relations
            USING (tenant_id IS NULL
                   OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                   OR current_setting('app.is_platform_admin', true) = 'true');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'definition_taxonomy'
                   AND policyname = 'definition_taxonomy_scope_isolation') THEN
        CREATE POLICY definition_taxonomy_scope_isolation ON definition_taxonomy
            USING (tenant_id IS NULL
                   OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                   OR current_setting('app.is_platform_admin', true) = 'true');
    END IF;
END $$;
