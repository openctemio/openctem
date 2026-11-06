-- Reverses 001740: recreates the legacy components and asset_components tables
-- from the catalog package rows, then removes the package rows and columns.
-- Packages seen by several tenants become one global components row again.

CREATE TABLE components (
    id uuid DEFAULT uuid_generate_v7() NOT NULL,
    purl character varying(500) NOT NULL,
    name character varying(255) NOT NULL,
    version character varying(100),
    ecosystem character varying(50) NOT NULL,
    description text,
    homepage character varying(500),
    vulnerability_count integer DEFAULT 0 NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_components_ecosystem CHECK (((ecosystem)::text = ANY ((ARRAY['npm'::character varying, 'maven'::character varying, 'pypi'::character varying, 'go'::character varying, 'cargo'::character varying, 'nuget'::character varying, 'rubygems'::character varying, 'composer'::character varying, 'cocoapods'::character varying, 'hex'::character varying, 'pub'::character varying, 'swiftpm'::character varying, 'cran'::character varying, 'gradle'::character varying, 'sbt'::character varying, 'packagist'::character varying, 'homebrew'::character varying, 'other'::character varying])::text[])))
);

CREATE TABLE asset_components (
    id uuid DEFAULT uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    component_id uuid,
    branch_id uuid,
    path character varying(1000),
    name character varying(255) NOT NULL,
    version character varying(100),
    ecosystem character varying(50) NOT NULL,
    package_manager character varying(50),
    namespace character varying(255),
    manifest_file character varying(255),
    manifest_path character varying(500),
    dependency_type character varying(50) DEFAULT 'direct'::character varying,
    license character varying(255),
    purl character varying(500),
    cpe character varying(500),
    vulnerability_count integer DEFAULT 0 NOT NULL,
    status character varying(50) DEFAULT 'active'::character varying,
    parent_component_id uuid,
    depth integer DEFAULT 0,
    is_direct boolean DEFAULT true,
    has_known_vulnerabilities boolean DEFAULT false,
    highest_severity character varying(20),
    risk_score integer DEFAULT 0,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_component_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'deprecated'::character varying, 'end_of_life'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT chk_dependency_type CHECK (((dependency_type)::text = ANY ((ARRAY['direct'::character varying, 'transitive'::character varying, 'dev'::character varying, 'optional'::character varying, 'peer'::character varying, 'build'::character varying])::text[]))),
    CONSTRAINT chk_ecosystem CHECK (((ecosystem)::text = ANY ((ARRAY['npm'::character varying, 'maven'::character varying, 'pypi'::character varying, 'go'::character varying, 'cargo'::character varying, 'nuget'::character varying, 'rubygems'::character varying, 'composer'::character varying, 'cocoapods'::character varying, 'hex'::character varying, 'pub'::character varying, 'swiftpm'::character varying, 'cran'::character varying, 'gradle'::character varying, 'sbt'::character varying, 'packagist'::character varying, 'homebrew'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT chk_no_self_parent CHECK (((parent_component_id IS NULL) OR (parent_component_id <> id)))
);

COMMENT ON TABLE components IS 'Global component registry with PURL-based deduplication';
COMMENT ON COLUMN components.purl IS 'Package URL (RFC) - unique identifier for the component';
COMMENT ON TABLE asset_components IS 'Software components and dependencies (SBOM)';
ALTER TABLE ONLY components ADD CONSTRAINT components_pkey PRIMARY KEY (id);
ALTER TABLE ONLY components ADD CONSTRAINT uq_components_purl UNIQUE (purl);
ALTER TABLE ONLY asset_components ADD CONSTRAINT asset_components_pkey PRIMARY KEY (id);

-- One global row per package URL (the first version row wins its id).
INSERT INTO components (id, purl, name, version, ecosystem, created_at, updated_at)
SELECT DISTINCT ON (v.purl) v.id, left(v.purl, 500), left(p.name, 255), NULLIF(left(v.raw, 100), ''),
       COALESCE(m.ecosystem, 'other'), v.created_at, v.created_at
  FROM software_versions v
  JOIN software_products p ON p.id = v.product_id
  LEFT JOIN (VALUES
        ('npm', 'npm'), ('maven', 'maven'), ('pypi', 'pypi'), ('golang', 'go'),
        ('cargo', 'cargo'), ('nuget', 'nuget'), ('gem', 'rubygems'), ('composer', 'composer'),
        ('cocoapods', 'cocoapods'), ('hex', 'hex'), ('pub', 'pub'), ('swift', 'swiftpm'),
        ('cran', 'cran'), ('brew', 'homebrew')
       ) AS m(purl_type, ecosystem) ON m.purl_type = p.purl_type
 WHERE v.purl IS NOT NULL
 ORDER BY v.purl, v.created_at, v.id;

CREATE TABLE component_rollback_map AS
SELECT v.id AS version_id, c.id AS component_id
  FROM software_versions v
  JOIN components c ON c.purl = left(v.purl, 500)
 WHERE v.purl IS NOT NULL;

INSERT INTO asset_components (id, tenant_id, asset_id, component_id, path, name, version, ecosystem,
                              manifest_path, dependency_type, license, purl, depth, is_direct,
                              created_at, updated_at)
SELECT DISTINCT ON (s.tenant_id, s.asset_id, c.name, c.version) s.id, s.tenant_id, s.asset_id, m.component_id, NULLIF(left(s.location, 1000), ''), c.name, c.version,
       c.ecosystem, NULLIF(left(s.location, 500), ''),
       CASE WHEN s.dep_scope = 'development' THEN 'dev' WHEN s.dep_scope = 'optional' THEN 'optional'
            WHEN s.dep_scope = 'build' THEN 'build' WHEN s.relationship = 'transitive' THEN 'transitive'
            ELSE 'direct' END,
       NULLIF(left(array_to_string(s.licenses, ', '), 255), ''), c.purl, COALESCE(s.depth, 0),
       COALESCE(s.relationship, 'direct') <> 'transitive', s.created_at, s.updated_at
  FROM asset_software s
  JOIN component_rollback_map m ON m.version_id = s.software_version_id
  JOIN components c ON c.id = m.component_id
 WHERE s.source = 'package'
ON CONFLICT DO NOTHING;

UPDATE asset_components ac SET parent_component_id = e.parent_id
  FROM (SELECT DISTINCT ON (child_id) child_id, parent_id FROM asset_software_edges ORDER BY child_id, parent_id) e
 WHERE ac.id = e.child_id AND EXISTS (SELECT 1 FROM asset_components p WHERE p.id = e.parent_id);

DROP TRIGGER trg_findings_component_scope ON findings;
DROP FUNCTION findings_component_scope_check();
ALTER TABLE findings DROP CONSTRAINT findings_component_id_fkey;
UPDATE findings f SET component_id = m.component_id
  FROM component_rollback_map m
 WHERE f.component_id = m.version_id;
UPDATE findings f SET component_id = NULL
 WHERE f.component_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM components c WHERE c.id = f.component_id);
ALTER TABLE ONLY findings ADD CONSTRAINT findings_component_id_fkey
    FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE SET NULL;
COMMENT ON COLUMN findings.component_id IS NULL;
DROP TABLE component_rollback_map;

CREATE INDEX idx_asset_components_branch ON asset_components USING btree (branch_id);
CREATE INDEX idx_asset_components_depth ON asset_components USING btree (asset_id, depth);
CREATE INDEX idx_asset_components_direct_deps ON asset_components USING btree (asset_id, component_id) WHERE (depth = 0);
CREATE INDEX idx_asset_components_ecosystem ON asset_components USING btree (ecosystem);
CREATE INDEX idx_asset_components_license ON asset_components USING btree (license);
CREATE INDEX idx_asset_components_name ON asset_components USING btree (name);
CREATE INDEX idx_asset_components_parent ON asset_components USING btree (parent_component_id);
CREATE INDEX idx_asset_components_purl ON asset_components USING btree (purl);
CREATE INDEX idx_asset_components_risk ON asset_components USING btree (risk_score DESC);
CREATE INDEX idx_asset_components_risk_query ON asset_components USING btree (asset_id, dependency_type, depth);
CREATE INDEX idx_asset_components_tenant_asset ON asset_components USING btree (tenant_id, asset_id);
CREATE INDEX idx_asset_components_tenant_component ON asset_components USING btree (tenant_id, component_id) WHERE (component_id IS NOT NULL);
CREATE INDEX idx_asset_components_vuln_count ON asset_components USING btree (vulnerability_count DESC);
CREATE INDEX idx_components_ecosystem ON components USING btree (ecosystem);
CREATE INDEX idx_components_name ON components USING btree (name);
CREATE INDEX idx_components_vuln_count ON components USING btree (vulnerability_count DESC);
CREATE UNIQUE INDEX idx_uq_asset_component ON asset_components USING btree (tenant_id, asset_id, name, version, COALESCE(branch_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE UNIQUE INDEX uq_asset_components_asset_component_path ON asset_components USING btree (asset_id, component_id, path);
ALTER TABLE ONLY asset_components ADD CONSTRAINT asset_components_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE;
ALTER TABLE ONLY asset_components ADD CONSTRAINT asset_components_branch_id_fkey FOREIGN KEY (branch_id) REFERENCES repository_branches(id) ON DELETE SET NULL;
ALTER TABLE ONLY asset_components ADD CONSTRAINT asset_components_parent_component_id_fkey FOREIGN KEY (parent_component_id) REFERENCES asset_components(id) ON DELETE SET NULL;
ALTER TABLE ONLY asset_components ADD CONSTRAINT asset_components_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE ONLY asset_components ADD CONSTRAINT fk_asset_components_tenant_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES assets(tenant_id, id) ON DELETE CASCADE;
CREATE TRIGGER trigger_asset_components_updated_at BEFORE UPDATE ON asset_components FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER trigger_components_updated_at BEFORE UPDATE ON components FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE POLICY asset_components_tenant_isolation ON asset_components USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE FUNCTION update_repository_component_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  target_asset_id UUID;
BEGIN
  target_asset_id := COALESCE(NEW.asset_id, OLD.asset_id);

  UPDATE asset_repositories SET
    component_count = (SELECT COUNT(*) FROM asset_components WHERE asset_id = target_asset_id),
    vulnerable_component_count = (SELECT COUNT(*) FROM asset_components WHERE asset_id = target_asset_id AND has_known_vulnerabilities = true)
  WHERE asset_id = target_asset_id
    AND EXISTS (SELECT 1 FROM assets a WHERE a.id = target_asset_id);

  RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE TRIGGER trg_update_repository_component_count AFTER INSERT OR DELETE OR UPDATE OF has_known_vulnerabilities ON asset_components FOR EACH ROW EXECUTE FUNCTION update_repository_component_count();

-- Remove the package rows and the new columns.
DROP TABLE asset_software_edges;
DROP FUNCTION asset_software_edges_scope_check();
DELETE FROM asset_software WHERE source = 'package';
DELETE FROM software_products WHERE purl_type IS NOT NULL;
DROP INDEX idx_asset_software_packages;
ALTER TABLE asset_software DROP CONSTRAINT chk_asset_software_package_fields;
ALTER TABLE asset_software DROP COLUMN relationship, DROP COLUMN dep_scope, DROP COLUMN depth,
    DROP COLUMN licenses, DROP COLUMN channel;
DELETE FROM asset_software WHERE length(location) > 64;
ALTER TABLE asset_software DROP CONSTRAINT asset_software_location_check;
ALTER TABLE asset_software ADD CONSTRAINT asset_software_location_check CHECK (length(location) <= 64);
ALTER TABLE asset_software DROP CONSTRAINT asset_software_source_check;
ALTER TABLE asset_software ADD CONSTRAINT asset_software_source_check
    CHECK (source IN ('technology', 'service', 'open_port', 'os'));
COMMENT ON COLUMN asset_software.location IS NULL;

DROP INDEX idx_software_versions_purl;
ALTER TABLE software_versions DROP COLUMN purl;
DELETE FROM software_versions WHERE length(raw) > 64;
ALTER TABLE software_versions DROP CONSTRAINT software_versions_raw_check;
ALTER TABLE software_versions ADD CONSTRAINT software_versions_raw_check CHECK (length(raw) <= 64);

DROP INDEX ux_software_products_tenant_purl;
DROP INDEX ux_software_products_global_purl;
DROP INDEX ux_software_products_tenant_name;
CREATE UNIQUE INDEX ux_software_products_tenant_name ON software_products (tenant_id, lower(name))
    WHERE tenant_id IS NOT NULL AND cpe_vendor IS NULL;
COMMENT ON COLUMN software_products.purl_namespace IS NULL;
ALTER TABLE software_products DROP CONSTRAINT chk_software_products_purl;
ALTER TABLE software_products DROP COLUMN description, DROP COLUMN homepage;
UPDATE software_products SET source = 'nvd' WHERE source = 'osv';
ALTER TABLE software_products DROP CONSTRAINT software_products_source_check;
ALTER TABLE software_products ADD CONSTRAINT software_products_source_check
    CHECK (source IN ('curated', 'nvd', 'observed'));
