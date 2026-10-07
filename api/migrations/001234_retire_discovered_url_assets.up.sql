-- Retire discovered_url assets (docs/rfcs/RFC-056-web-attack-surface.md WS2).
--
-- A crawled URL is a web endpoint under its origin now (migration 001230);
-- ingest no longer creates discovered_url assets. Existing ones become
-- endpoints, then are deleted (one-step upgrade, minimal back-compat):
--
--   1. each URL's origin (scheme://host[:port], lower-cased, default port
--      dropped: the origin identity of research/63 T10) gets an
--      http_service asset in the same tenant when it has none;
--   2. each URL becomes a GET endpoint under its origin: the path without
--      query or fragment, integer and UUID segments templated, query
--      NAMES kept as parameters (values never);
--   3. findings and exposures on a URL asset move to its origin asset;
--   4. the URL assets are deleted (their other references cascade).
--
-- Small or empty on every known deployment (live: 0 rows). Ingest
-- recomputes templates with ctis/weburl on the next crawl; a template this
-- SQL wrote differently is retired by the 30-day gone sweep.

CREATE TEMP TABLE _url_assets ON COMMIT DROP AS
SELECT a.id, a.tenant_id, a.name AS url,
       regexp_replace(regexp_replace(lower(substring(a.name FROM '^(https?://[^/?#]+)')),
           '^(https://.+):443$', '\1'), '^(http://.+):80$', '\1') AS origin,
       COALESCE(NULLIF(rtrim(substring(a.name FROM '^https?://[^/?#]+(/[^?#]*)'), '/'), ''), '/') AS path,
       substring(a.name FROM '\?([^#]*)') AS query
  FROM assets a
 WHERE a.sub_type = 'discovered_url' AND a.name ~* '^https?://[^/?#]+';

-- Origins that have no http_service asset yet.
INSERT INTO assets (id, tenant_id, name, asset_type, sub_type)
SELECT uuid_generate_v7(), u.tenant_id, u.origin, 'service', 'http'
  FROM (SELECT DISTINCT tenant_id, origin FROM _url_assets) u
 WHERE NOT EXISTS (SELECT 1 FROM assets o WHERE o.tenant_id = u.tenant_id AND o.name = u.origin AND o.deleted_at IS NULL);

CREATE TEMP TABLE _url_map ON COMMIT DROP AS
SELECT u.id AS url_id, u.tenant_id, u.path, u.query,
       (SELECT o.id FROM assets o WHERE o.tenant_id = u.tenant_id AND o.name = u.origin AND o.deleted_at IS NULL
         ORDER BY (o.sub_type = 'http') DESC, o.created_at LIMIT 1) AS origin_id,
       regexp_replace(regexp_replace(u.path,
           '/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)', '/{uuid}', 'g'),
           '/[0-9]+(?=/|$)', '/{int}', 'g') AS template
  FROM _url_assets u;

INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash,
                           kind, sources, example_path, first_seen_at, last_seen_at)
SELECT DISTINCT ON (m.tenant_id, m.origin_id, m.template)
       uuid_generate_v7(), m.tenant_id, m.origin_id, 'GET', left(m.template, 2048),
       encode(sha256(convert_to('GET' || chr(10) || m.template, 'UTF8')), 'hex'),
       encode(sha256(convert_to(m.template, 'UTF8')), 'hex'),
       'page', ARRAY['crawl'], NULL, now(), now()
  FROM _url_map m
 WHERE m.origin_id IS NOT NULL AND left(m.template, 1) = '/'
ON CONFLICT (tenant_id, origin_asset_id, template_hash) DO NOTHING;

INSERT INTO web_endpoint_params (tenant_id, endpoint_id, location, name, sources)
SELECT DISTINCT e.tenant_id, e.id, 'query', left(split_part(kv, '=', 1), 128), ARRAY['crawl']
  FROM _url_map m
  JOIN web_endpoints e ON e.tenant_id = m.tenant_id AND e.origin_asset_id = m.origin_id
       AND e.template_hash = encode(sha256(convert_to('GET' || chr(10) || m.template, 'UTF8')), 'hex')
  CROSS JOIN LATERAL unnest(string_to_array(COALESCE(m.query, ''), '&')) AS kv
 WHERE split_part(kv, '=', 1) <> ''
ON CONFLICT DO NOTHING;

UPDATE web_endpoints e SET param_count = c.n
  FROM (SELECT endpoint_id, count(*) AS n FROM web_endpoint_params GROUP BY endpoint_id) c
 WHERE e.id = c.endpoint_id AND e.param_count <> c.n;

UPDATE findings f SET asset_id = m.origin_id
  FROM _url_map m WHERE f.asset_id = m.url_id AND f.tenant_id = m.tenant_id AND m.origin_id IS NOT NULL;

UPDATE exposure_events x SET asset_id = m.origin_id
  FROM _url_map m WHERE x.asset_id = m.url_id AND x.tenant_id = m.tenant_id AND m.origin_id IS NOT NULL;

DELETE FROM assets a USING _url_map m WHERE a.id = m.url_id AND m.origin_id IS NOT NULL;
