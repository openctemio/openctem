-- Asset technologies (RFC-112): fill asset_technologies from the
-- technologies existing assets show (properties.technologies, a list of
-- "Name:version" strings or {name, version} objects). One row per asset and
-- normalised name: a known version beats none.
-- Category starts as 'other'; the asset-technology-backfill controller
-- classifies the rows (the curated list lives in code) and removes the
-- component links ingest no longer creates.
--
-- Reads assets (no lock beyond ACCESS SHARE) and writes only the new table.
-- Names are trimmed, single-spaced, at most 128 bytes, without control
-- characters; versions over 64 bytes are dropped.
WITH raw AS (
    SELECT a.tenant_id, a.id AS asset_id, a.first_seen, a.last_seen,
           CASE jsonb_typeof(e.v)
                WHEN 'string' THEN e.v #>> '{}'
                WHEN 'object' THEN CASE WHEN COALESCE(e.v ->> 'version', '') = '' THEN e.v ->> 'name'
                                        ELSE (e.v ->> 'name') || ':' || (e.v ->> 'version') END
           END AS el
      FROM assets a
      CROSS JOIN LATERAL jsonb_array_elements(a.properties -> 'technologies') AS e(v)
     WHERE jsonb_typeof(a.properties -> 'technologies') = 'array'
),
split AS (
    SELECT tenant_id, asset_id, first_seen, last_seen,
           regexp_replace(btrim(regexp_replace(el, ':\s*[vV]?[0-9][^:]*$', '')), '\s+', ' ', 'g') AS name,
           COALESCE(btrim(substring(el FROM ':\s*([vV]?[0-9][^:]*)$')), '') AS version
      FROM raw
     WHERE el IS NOT NULL
),
clean AS (
    SELECT tenant_id, asset_id, first_seen, last_seen, name, lower(name) AS name_key,
           CASE WHEN length(version) <= 64 AND version !~ '[[:cntrl:]]' THEN version ELSE '' END AS version
      FROM split
     WHERE length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'
)
INSERT INTO asset_technologies (tenant_id, asset_id, name_key, name, version, category, confidence, source, first_seen, last_seen)
SELECT DISTINCT ON (tenant_id, asset_id, name_key)
       tenant_id, asset_id, name_key, name, version, 'other', 0, '',
       LEAST(first_seen, last_seen), GREATEST(first_seen, last_seen)
  FROM clean
 ORDER BY tenant_id, asset_id, name_key, (version = ''), version DESC
ON CONFLICT ON CONSTRAINT pk_asset_technologies DO NOTHING;

-- Tenants the asset-technology-backfill controller has done, by version.
CREATE TABLE asset_technology_backfill (
    tenant_id     UUID        NOT NULL PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version       INTEGER     NOT NULL,
    technologies  INTEGER     NOT NULL DEFAULT 0,
    classified    INTEGER     NOT NULL DEFAULT 0,
    links_removed INTEGER     NOT NULL DEFAULT 0,
    completed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE asset_technology_backfill IS
    'RFC-112: tenants whose technologies the backfill classified and whose non-software component links it removed.';
