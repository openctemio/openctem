-- expand-contract-ok: one-step move of the legacy component tables into the software catalog (owner rule: minimal back-compat); the API stops during the deploy and ships the new readers in the same release (changelog upgrade note).
-- Software components move into the software catalog (RFC-070).
--
-- Packages become catalog products with a package URL identity and versions;
-- where an asset uses a package is an asset_software row (source 'package')
-- and the dependency graph is asset_software_edges. The legacy global
-- components table (one row per purl@version, shared by every tenant and
-- created from any tenant's report) and asset_components are copied per
-- tenant and dropped. Every copied package is tenant-private: a global
-- package product is created only by the vulnerability feed.
--
-- Destructive: the API must be stopped during the deploy (old code reads the
-- dropped tables). The description and homepage of the old global rows are not
-- copied: one tenant's report wrote them and every tenant read them.

-- 1. Catalog: package identity, longer versions, the canonical purl.

ALTER TABLE software_products DROP CONSTRAINT software_products_source_check;
ALTER TABLE software_products ADD CONSTRAINT software_products_source_check
    CHECK (source IN ('curated', 'nvd', 'osv', 'observed'));
ALTER TABLE software_products ADD CONSTRAINT chk_software_products_purl
    CHECK ((purl_type IS NULL) = (purl_name IS NULL)
       AND (purl_type IS NULL OR (purl_namespace IS NOT NULL AND length(purl_type) >= 1 AND length(purl_name) >= 1)));

ALTER TABLE software_products
    ADD COLUMN description TEXT CHECK (length(description) <= 2000),
    ADD COLUMN homepage    TEXT CHECK (length(homepage) <= 512);
COMMENT ON COLUMN software_products.description IS
    'Package description: from the vulnerability feed for a global product, from the tenant''s own reports for a private one.';

DROP INDEX ux_software_products_tenant_name;
CREATE UNIQUE INDEX ux_software_products_tenant_name ON software_products (tenant_id, lower(name))
    WHERE tenant_id IS NOT NULL AND cpe_vendor IS NULL AND purl_type IS NULL;
CREATE UNIQUE INDEX ux_software_products_global_purl ON software_products (purl_type, purl_namespace, purl_name)
    WHERE tenant_id IS NULL AND purl_type IS NOT NULL;
CREATE UNIQUE INDEX ux_software_products_tenant_purl ON software_products (tenant_id, purl_type, purl_namespace, purl_name)
    WHERE tenant_id IS NOT NULL AND purl_type IS NOT NULL;
COMMENT ON COLUMN software_products.purl_namespace IS
    'Package URL namespace ('''' when the type has none). With purl_type and purl_name, the package identity (RFC-070).';

ALTER TABLE software_versions DROP CONSTRAINT software_versions_raw_check;
ALTER TABLE software_versions ADD CONSTRAINT software_versions_raw_check CHECK (length(raw) <= 128);
ALTER TABLE software_versions ADD COLUMN purl TEXT CHECK (length(purl) <= 600);
CREATE INDEX idx_software_versions_purl ON software_versions (purl) WHERE purl IS NOT NULL;
COMMENT ON COLUMN software_versions.purl IS
    'Canonical package URL with version, no qualifiers (package versions only).';

-- 2. Where-used columns for packages.

ALTER TABLE asset_software DROP CONSTRAINT asset_software_source_check;
ALTER TABLE asset_software ADD CONSTRAINT asset_software_source_check
    CHECK (source IN ('technology', 'service', 'open_port', 'os', 'package'));
ALTER TABLE asset_software DROP CONSTRAINT asset_software_location_check;
ALTER TABLE asset_software ADD CONSTRAINT asset_software_location_check CHECK (length(location) <= 512);
ALTER TABLE asset_software
    ADD COLUMN relationship TEXT CHECK (relationship IN ('direct', 'transitive', 'unknown')),
    ADD COLUMN dep_scope    TEXT CHECK (dep_scope IN ('runtime', 'development', 'test', 'optional', 'build', 'provided')),
    ADD COLUMN depth        SMALLINT CHECK (depth BETWEEN 0 AND 32),
    ADD COLUMN licenses     TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(licenses) <= 16),
    ADD COLUMN channel      TEXT CHECK (channel IN ('sensor', 'ci', 'sbom_upload', 'finding_import', 'integration'));
ALTER TABLE asset_software ADD CONSTRAINT chk_asset_software_package_fields
    CHECK (source = 'package' OR (relationship IS NULL AND dep_scope IS NULL AND depth IS NULL AND cardinality(licenses) = 0));
CREATE INDEX idx_asset_software_packages ON asset_software (tenant_id, product_id) WHERE source = 'package';
COMMENT ON COLUMN asset_software.location IS
    'Where on the asset: "tcp/443", '''' for host level; for packages the manifest or lock file path.';

-- 3. Dependency graph: every parent of a link, so every introduction path.

CREATE TABLE asset_software_edges (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id  UUID NOT NULL,
    parent_id UUID NOT NULL REFERENCES asset_software(id) ON DELETE CASCADE,
    child_id  UUID NOT NULL REFERENCES asset_software(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_id, child_id),
    CONSTRAINT chk_asset_software_edges_no_self CHECK (parent_id <> child_id),
    CONSTRAINT fk_asset_software_edges_tenant_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_asset_software_edges_child ON asset_software_edges (child_id);
CREATE INDEX idx_asset_software_edges_asset ON asset_software_edges (tenant_id, asset_id);
COMMENT ON TABLE asset_software_edges IS
    'Package dependency graph of one asset (RFC-070): parent link depends on child link. Both ends are links of the same tenant and asset.';

CREATE FUNCTION asset_software_edges_scope_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM asset_software
         WHERE id IN (NEW.parent_id, NEW.child_id)
           AND tenant_id = NEW.tenant_id AND asset_id = NEW.asset_id) <> 2 THEN
        RAISE EXCEPTION 'dependency edge ends must be links of the same tenant and asset' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_asset_software_edges_scope BEFORE INSERT OR UPDATE ON asset_software_edges
    FOR EACH ROW EXECUTE FUNCTION asset_software_edges_scope_check();

-- 4. Copy the legacy rows, per tenant.

-- Every (tenant, package version) the legacy tables hold: links, and findings
-- whose component has no link in their tenant.
CREATE TABLE component_migration_src AS
SELECT DISTINCT ac.tenant_id, ac.component_id,
       COALESCE(NULLIF(c.purl, ''), NULLIF(ac.purl, '')) AS purl,
       COALESCE(c.name, ac.name) AS name,
       COALESCE(NULLIF(c.version, ''), NULLIF(ac.version, ''), '') AS version,
       COALESCE(c.ecosystem, ac.ecosystem) AS ecosystem,
       ac.id AS link_id
  FROM asset_components ac
  LEFT JOIN components c ON c.id = ac.component_id
UNION ALL
SELECT DISTINCT f.tenant_id, f.component_id, c.purl, c.name, COALESCE(c.version, ''), c.ecosystem, NULL::uuid
  FROM findings f
  JOIN components c ON c.id = f.component_id;

-- Parse the package URL (pkg:type/namespace/name@version?qualifiers#subpath);
-- rows without one get a synthetic identity from the ecosystem and name.
CREATE TABLE component_migration_parsed AS
WITH base AS (
    SELECT s.*,
           CASE WHEN s.purl ILIKE 'pkg:%/%'
                THEN substr(split_part(split_part(s.purl, '#', 1), '?', 1), 5)
                ELSE COALESCE(m.purl_type, 'generic') || '/' || replace(s.name, '/', '%2F') || '@' || s.version
           END AS body
      FROM component_migration_src s
      LEFT JOIN (VALUES
            ('npm', 'npm'), ('maven', 'maven'), ('pypi', 'pypi'), ('go', 'golang'),
            ('cargo', 'cargo'), ('nuget', 'nuget'), ('rubygems', 'gem'), ('composer', 'composer'),
            ('cocoapods', 'cocoapods'), ('hex', 'hex'), ('pub', 'pub'), ('swiftpm', 'swift'),
            ('cran', 'cran'), ('gradle', 'maven'), ('sbt', 'maven'), ('packagist', 'composer'),
            ('homebrew', 'brew')
           ) AS m(ecosystem, purl_type) ON m.ecosystem = s.ecosystem
), split AS (
    SELECT b.*,
           regexp_replace(b.body, '@[^@/]*$', '') AS path,
           substring(b.body from '@([^@/]*)$') AS purl_version
      FROM base b
), parts AS (
    SELECT s.*,
           lower(split_part(s.path, '/', 1)) AS ptype,
           substr(s.path, length(split_part(s.path, '/', 1)) + 2) AS rest
      FROM split s
), named AS (
    SELECT p.*,
           replace(replace(replace(replace(regexp_replace(p.rest, '^.*/', ''), '%40', '@'), '%2B', '+'), '%20', ' '), '%2F', '/') AS pname,
           CASE WHEN position('/' in p.rest) > 0
                THEN replace(replace(regexp_replace(p.rest, '/[^/]*$', ''), '%40', '@'), '%2F', '/')
                ELSE '' END AS pns
      FROM parts p
)
SELECT n.tenant_id, n.component_id, n.link_id, n.name,
       n.ptype AS purl_type,
       left(CASE WHEN n.ptype IN ('npm', 'pypi', 'github', 'bitbucket', 'composer') THEN lower(n.pns) ELSE n.pns END, 256) AS purl_namespace,
       left(CASE WHEN n.ptype = 'pypi' THEN replace(lower(n.pname), '_', '-')
                 WHEN n.ptype IN ('npm', 'github', 'bitbucket', 'composer') THEN lower(n.pname)
                 ELSE n.pname END, 256) AS purl_name,
       left(COALESCE(NULLIF(n.version, ''), replace(n.purl_version, '%2B', '+'), ''), 128) AS version,
       CASE n.ptype WHEN 'npm' THEN 'npm' WHEN 'pypi' THEN 'pep440' WHEN 'maven' THEN 'maven'
                    WHEN 'golang' THEN 'go' WHEN 'deb' THEN 'deb' WHEN 'rpm' THEN 'rpm' WHEN 'apk' THEN 'apk'
                    WHEN 'cargo' THEN 'semver' WHEN 'nuget' THEN 'semver' ELSE 'generic' END AS scheme
  FROM named n
 WHERE n.ptype ~ '^[a-z][a-z0-9.+-]{0,31}$' AND n.pname <> '';

INSERT INTO software_products (tenant_id, part, vendor, name, purl_type, purl_namespace, purl_name, source)
SELECT DISTINCT ON (tenant_id, purl_type, purl_namespace, purl_name)
       tenant_id, 'a', left(purl_namespace, 128), left(COALESCE(NULLIF(name, ''), purl_name), 200),
       purl_type, purl_namespace, purl_name, 'observed'
  FROM component_migration_parsed
 ORDER BY tenant_id, purl_type, purl_namespace, purl_name, name
ON CONFLICT DO NOTHING;

INSERT INTO software_versions (product_id, tenant_id, raw, normalized, scheme, purl)
SELECT DISTINCT ON (p.id, mp.scheme, mp.version)
       p.id, mp.tenant_id, mp.version, NULLIF(mp.version, ''), mp.scheme,
       'pkg:' || mp.purl_type || '/'
           || CASE WHEN mp.purl_namespace <> '' THEN mp.purl_namespace || '/' ELSE '' END
           || mp.purl_name || CASE WHEN mp.version <> '' THEN '@' || mp.version ELSE '' END
  FROM component_migration_parsed mp
  JOIN software_products p ON p.tenant_id = mp.tenant_id AND p.purl_type = mp.purl_type
                          AND p.purl_namespace = mp.purl_namespace AND p.purl_name = mp.purl_name
ON CONFLICT DO NOTHING;

CREATE TABLE component_migration_map AS
SELECT DISTINCT mp.tenant_id, mp.component_id, mp.link_id, p.id AS product_id, v.id AS version_id
  FROM component_migration_parsed mp
  JOIN software_products p ON p.tenant_id = mp.tenant_id AND p.purl_type = mp.purl_type
                          AND p.purl_namespace = mp.purl_namespace AND p.purl_name = mp.purl_name
  JOIN software_versions v ON v.product_id = p.id AND v.scheme = mp.scheme
                          AND COALESCE(v.normalized, 'raw:' || v.raw) = COALESCE(NULLIF(mp.version, ''), 'raw:' || mp.version)
                          AND v.qualifier = '' AND v.edition = '';

-- Links: one per (asset, version, location); the newest legacy row wins.
CREATE TABLE component_migration_links AS
SELECT ac.id AS old_id, ac.tenant_id, ac.asset_id, m.product_id, m.version_id,
       left(COALESCE(NULLIF(ac.manifest_path, ''), NULLIF(ac.path, ''), NULLIF(ac.manifest_file, ''), ''), 512) AS location,
       left(COALESCE(NULLIF(ac.purl, ''), ac.name || '@' || COALESCE(ac.version, '')), 512) AS evidence,
       CASE WHEN COALESCE(ac.purl, '') <> '' THEN 100 ELSE 80 END AS confidence,
       CASE WHEN ac.dependency_type = 'transitive' OR ac.is_direct = false OR COALESCE(ac.depth, 0) > 0
            THEN 'transitive' ELSE 'direct' END AS relationship,
       CASE ac.dependency_type WHEN 'dev' THEN 'development' WHEN 'optional' THEN 'optional'
                               WHEN 'build' THEN 'build' WHEN 'peer' THEN 'optional' ELSE NULL END AS dep_scope,
       LEAST(GREATEST(COALESCE(ac.depth, 0), 0), 32) AS depth,
       COALESCE((SELECT array_agg(DISTINCT left(btrim(l), 128)) FROM unnest(string_to_array(ac.license, ',')) AS l
                  WHERE btrim(l) <> ''), '{}') AS licenses,
       ac.created_at, ac.updated_at,
       row_number() OVER (PARTITION BY ac.tenant_id, ac.asset_id, m.version_id,
                          left(COALESCE(NULLIF(ac.manifest_path, ''), NULLIF(ac.path, ''), NULLIF(ac.manifest_file, ''), ''), 512)
                          ORDER BY ac.updated_at DESC, ac.id) AS rn
  FROM asset_components ac
  JOIN component_migration_map m ON m.link_id = ac.id;

INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location, source, evidence,
                            confidence, relationship, dep_scope, depth, licenses, first_seen_at, last_seen_at,
                            created_at, updated_at)
SELECT tenant_id, asset_id, product_id, version_id, location, 'package', evidence, confidence, relationship,
       dep_scope, depth, licenses[1:16], created_at, updated_at, created_at, updated_at
  FROM component_migration_links
 WHERE rn = 1
ON CONFLICT (tenant_id, asset_id, software_version_id, location) DO NOTHING;

CREATE TABLE component_migration_link_ids AS
SELECT l.old_id, s.id AS new_id
  FROM component_migration_links l
  JOIN asset_software s ON s.tenant_id = l.tenant_id AND s.asset_id = l.asset_id
                       AND s.software_version_id = l.version_id AND s.location = l.location;

INSERT INTO asset_software_edges (tenant_id, asset_id, parent_id, child_id)
SELECT DISTINCT ac.tenant_id, ac.asset_id, pm.new_id, cm.new_id
  FROM asset_components ac
  JOIN asset_components parent ON parent.id = ac.parent_component_id
                              AND parent.tenant_id = ac.tenant_id AND parent.asset_id = ac.asset_id
  JOIN component_migration_link_ids cm ON cm.old_id = ac.id
  JOIN component_migration_link_ids pm ON pm.old_id = parent.id
 WHERE pm.new_id <> cm.new_id
ON CONFLICT DO NOTHING;

-- Findings point at their tenant's version.
ALTER TABLE findings DROP CONSTRAINT findings_component_id_fkey;
UPDATE findings f
   SET component_id = m.version_id
  FROM (SELECT DISTINCT tenant_id, component_id, version_id FROM component_migration_map WHERE component_id IS NOT NULL) m
 WHERE f.component_id IS NOT NULL AND f.component_id = m.component_id AND f.tenant_id = m.tenant_id;
UPDATE findings f SET component_id = NULL
 WHERE f.component_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM software_versions v WHERE v.id = f.component_id);
ALTER TABLE findings ADD CONSTRAINT findings_component_id_fkey
    FOREIGN KEY (component_id) REFERENCES software_versions(id) ON DELETE SET NULL;
COMMENT ON COLUMN findings.component_id IS
    'The package version the finding is about (software_versions.id; global or the finding''s own tenant).';

CREATE FUNCTION findings_component_scope_check() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    version_tenant UUID;
BEGIN
    IF NEW.component_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT tenant_id INTO version_tenant FROM software_versions WHERE id = NEW.component_id;
    IF version_tenant IS NOT NULL AND version_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION 'finding component belongs to another tenant' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_findings_component_scope BEFORE INSERT OR UPDATE OF component_id, tenant_id ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_component_scope_check();

-- Repository counters: written by the package writer once per report.
UPDATE asset_repositories ar SET
    component_count = (SELECT count(*) FROM asset_software s
                        WHERE s.asset_id = ar.asset_id AND s.source = 'package' AND s.superseded_at IS NULL),
    vulnerable_component_count = (SELECT count(DISTINCT s.software_version_id) FROM asset_software s
                                   JOIN findings f ON f.tenant_id = s.tenant_id AND f.asset_id = s.asset_id
                                                  AND f.component_id = s.software_version_id
                                                  AND f.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate')
                                  WHERE s.asset_id = ar.asset_id AND s.source = 'package' AND s.superseded_at IS NULL);

-- 5. Drop the legacy tables and their helpers.

DROP TRIGGER IF EXISTS trg_update_repository_component_count ON asset_components;
DROP FUNCTION IF EXISTS update_repository_component_count();
DROP TABLE component_migration_link_ids;
DROP TABLE component_migration_links;
DROP TABLE component_migration_map;
DROP TABLE component_migration_parsed;
DROP TABLE component_migration_src;
DROP TABLE asset_components;
DROP TABLE components;
