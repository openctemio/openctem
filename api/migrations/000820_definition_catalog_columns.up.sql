-- The CVE catalog becomes a catalog of issue definitions, extended in place:
-- every existing row keeps its id, so every findings.vulnerability_id stays
-- valid (RFC-044 §5.1, decision D1).
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
--
-- Additive only. Every new column has a default that describes the rows that
-- exist today (global CVE entries), so the code already deployed keeps
-- inserting valid rows without knowing the columns exist. The per-row values
-- (external_id, origin, cvss_version, nicknames) are filled by 000822 in
-- batches; the constraints that need them are added NOT VALID here and
-- validated by 000825.
--
-- Scope and trust (RFC-044 §5.5, docs/architecture/global-catalog-trust.md):
--   tenant_id NULL      a global definition, platform-owned, read-only to tenants.
--   tenant_id = T       visible to tenant T only (custom rules, pentest issues,
--                       a rule id a sensor reported that no curated pack knows).
-- scope_tenant_id repeats tenant_id with the nil UUID for global rows. It
-- exists for foreign keys: a key column that is NULL is not checked, so the
-- tables that point at a definition (000823) reference (id, scope_tenant_id)
-- to prove the definition is global or their own tenant's. A trigger keeps it
-- equal to tenant_id and refuses to move a definition between scopes.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS tenant_id UUID,
    ADD COLUMN IF NOT EXISTS scope_tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS kind VARCHAR(30) NOT NULL DEFAULT 'vulnerability',
    ADD COLUMN IF NOT EXISTS namespace VARCHAR(100) NOT NULL DEFAULT 'CVE',
    ADD COLUMN IF NOT EXISTS external_id VARCHAR(512),
    ADD COLUMN IF NOT EXISTS lifecycle VARCHAR(20) NOT NULL DEFAULT 'published',
    ADD COLUMN IF NOT EXISTS merged_into UUID,
    ADD COLUMN IF NOT EXISTS merged_into_scope UUID,
    ADD COLUMN IF NOT EXISTS origin VARCHAR(20) NOT NULL DEFAULT 'report',
    ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(10),
    ADD COLUMN IF NOT EXISTS nicknames TEXT[] NOT NULL DEFAULT '{}';

-- A definition without a CVE (a rule, a template, a GHSA-only advisory) has
-- no cve_id. The existing UNIQUE (cve_id) constraint stays: NULLs never
-- conflict, so it is unique over the CVE rows only, and ON CONFLICT (cve_id)
-- in the deployed ingest keeps working unchanged.
ALTER TABLE vulnerabilities ALTER COLUMN cve_id DROP NOT NULL;

ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS fk_vulnerabilities_tenant,
    DROP CONSTRAINT IF EXISTS chk_vuln_kind,
    DROP CONSTRAINT IF EXISTS chk_vuln_namespace,
    DROP CONSTRAINT IF EXISTS chk_vuln_lifecycle,
    DROP CONSTRAINT IF EXISTS chk_vuln_origin,
    DROP CONSTRAINT IF EXISTS chk_vuln_scope_tenant,
    DROP CONSTRAINT IF EXISTS chk_vuln_origin_scope,
    DROP CONSTRAINT IF EXISTS chk_vuln_merged,
    DROP CONSTRAINT IF EXISTS chk_vuln_external_id,
    DROP CONSTRAINT IF EXISTS chk_vuln_cve_compat;

-- Every constraint is added NOT VALID: the rows that exist satisfy them
-- through the defaults (or once 000822 has run), and checking them here would
-- scan the catalog under this statement's exclusive lock. New and updated
-- rows are checked from now on; 000825 validates the existing ones without
-- blocking reads or writes.
ALTER TABLE vulnerabilities
    ADD CONSTRAINT fk_vulnerabilities_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT chk_vuln_kind CHECK (kind IN (
        'vulnerability', 'weakness', 'misconfiguration', 'exposure',
        'secret', 'compliance', 'malicious')) NOT VALID,
    -- CVE, GHSA, NUCLEI, OSV:PYSEC, CUSTOM:my-scanner (registry in
    -- pkg/domain/definition/namespace.go).
    ADD CONSTRAINT chk_vuln_namespace CHECK (
        namespace ~ '^[A-Z][A-Z0-9_]{0,31}(:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$') NOT VALID,
    ADD CONSTRAINT chk_vuln_lifecycle CHECK (lifecycle IN (
        'published', 'reserved', 'rejected', 'withdrawn', 'disputed',
        'deprecated', 'merged')) NOT VALID,
    ADD CONSTRAINT chk_vuln_origin CHECK (origin IN (
        'cve_list', 'nvd', 'osv', 'ghsa', 'kev', 'rule_catalog', 'report', 'tenant')) NOT VALID,
    ADD CONSTRAINT chk_vuln_scope_tenant CHECK (
        scope_tenant_id = COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)) NOT VALID,
    -- A tenant definition comes from that tenant's reports or users; a global
    -- one never comes from a tenant.
    ADD CONSTRAINT chk_vuln_origin_scope CHECK (
        (tenant_id IS NULL AND origin <> 'tenant')
        OR (tenant_id IS NOT NULL AND origin IN ('report', 'tenant'))) NOT VALID,
    -- merged <=> merged_into set, never into itself; the target is global or
    -- in the same tenant (merged_into_scope, foreign key below).
    ADD CONSTRAINT chk_vuln_merged CHECK (
        (lifecycle = 'merged') = (merged_into IS NOT NULL)
        AND (merged_into IS NULL) = (merged_into_scope IS NULL)
        AND (merged_into IS NULL OR merged_into <> id)
        AND (merged_into_scope IS NULL
             OR merged_into_scope IN ('00000000-0000-0000-0000-000000000000'::uuid, scope_tenant_id))) NOT VALID,
    ADD CONSTRAINT chk_vuln_external_id CHECK (
        external_id IS NOT NULL AND external_id <> '') NOT VALID,
    -- cve_id is the compat copy of the primary id of a CVE definition: set
    -- exactly on CVE rows, always global, always equal to external_id.
    ADD CONSTRAINT chk_vuln_cve_compat CHECK (
        (namespace = 'CVE') = (cve_id IS NOT NULL)
        AND (cve_id IS NULL OR (tenant_id IS NULL AND external_id = cve_id))) NOT VALID;

-- The deployed code inserts a CVE row with cve_id only. Fill the identity
-- columns from it, keep scope_tenant_id equal to tenant_id, and refuse to
-- change a definition's scope: moving a tenant definition to global would
-- publish that tenant's text to every tenant, and the reverse would take a
-- shared entry away from everyone else.
CREATE OR REPLACE FUNCTION vulnerabilities_definition_compat() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'the scope of definition % cannot change', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.cve_id IS NOT NULL AND NEW.external_id IS NULL THEN
        NEW.external_id := NEW.cve_id;
    END IF;
    NEW.scope_tenant_id := COALESCE(NEW.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trigger_vulnerabilities_definition_compat ON vulnerabilities;
CREATE TRIGGER trigger_vulnerabilities_definition_compat
    BEFORE INSERT OR UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION vulnerabilities_definition_compat();

COMMENT ON TABLE vulnerabilities IS
    'Issue definitions (RFC-044): the global CVE catalog plus every other definition kind. tenant_id NULL = global and platform-owned; set = visible to that tenant only. Renamed issue_definitions in a later release.';
COMMENT ON COLUMN vulnerabilities.tenant_id IS 'NULL for a global definition; the owning tenant for a tenant-scoped one (RFC-044 §5.5).';
COMMENT ON COLUMN vulnerabilities.scope_tenant_id IS 'tenant_id, or the nil UUID for a global definition. Maintained by trigger; referenced by same-scope foreign keys.';
COMMENT ON COLUMN vulnerabilities.kind IS 'RFC-044 §4.1: vulnerability, weakness, misconfiguration, exposure, secret, compliance, malicious.';
COMMENT ON COLUMN vulnerabilities.namespace IS 'Namespace of the primary identifier (CVE, GHSA, NUCLEI, OSV:<db>, CUSTOM:<tool>, ...).';
COMMENT ON COLUMN vulnerabilities.external_id IS 'Primary identifier inside namespace, normalized (CVE upper-case).';
COMMENT ON COLUMN vulnerabilities.cve_id IS 'Compat: external_id when namespace = CVE, else NULL.';
COMMENT ON COLUMN vulnerabilities.lifecycle IS 'published, reserved, rejected, withdrawn, disputed, deprecated, merged.';
COMMENT ON COLUMN vulnerabilities.merged_into IS 'The definition this one was folded into (lifecycle = merged).';
COMMENT ON COLUMN vulnerabilities.origin IS 'Who created the identity: a trusted feed (cve_list, nvd, osv, ghsa, kev), the rule-catalog import, a report (identity stub) or a tenant.';
COMMENT ON COLUMN vulnerabilities.nicknames IS 'Common names ("Log4Shell"). Not identifiers; never used to resolve or merge.';

-- RLS shadow policy (not enabled, like the others; see migration 000157):
-- a definition is visible when it is global or the caller's tenant's.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies
                   WHERE tablename = 'vulnerabilities'
                     AND policyname = 'vulnerabilities_scope_isolation') THEN
        CREATE POLICY vulnerabilities_scope_isolation ON vulnerabilities
            USING (tenant_id IS NULL
                   OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                   OR current_setting('app.is_platform_admin', true) = 'true');
    END IF;
END $$;
