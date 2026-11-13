-- Components a scanner reported with a package URL but no ecosystem label
-- (trivy fs) were stored with ecosystem 'other'. Classify them from the
-- package URL type, as ingest now does (component.EcosystemFromPURL), on the
-- shared components and on each asset's copy. Rows whose type is outside our
-- ecosystems (deb, apk, rpm, ...) stay 'other'. Idempotent.

UPDATE components c
   SET ecosystem = m.ecosystem
  FROM (VALUES
        ('npm', 'npm'), ('maven', 'maven'), ('pypi', 'pypi'), ('golang', 'go'),
        ('cargo', 'cargo'), ('nuget', 'nuget'), ('gem', 'rubygems'),
        ('composer', 'composer'), ('hex', 'hex'), ('cocoapods', 'cocoapods'),
        ('swift', 'swiftpm'), ('pub', 'pub'), ('cran', 'cran')
       ) AS m(purl_type, ecosystem)
 WHERE c.ecosystem = 'other'
   AND c.purl LIKE 'pkg:%/%'
   AND lower(split_part(substr(c.purl, 5), '/', 1)) = m.purl_type;

UPDATE asset_components ac
   SET ecosystem = c.ecosystem
  FROM components c
 WHERE ac.component_id = c.id
   AND ac.ecosystem = 'other'
   AND c.ecosystem <> 'other';
