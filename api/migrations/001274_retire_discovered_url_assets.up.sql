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
-- Small or empty on every known deployment (live: 0 rows), so one row at a
-- time. Ingest recomputes templates with ctis/weburl on the next crawl; a
-- template this SQL wrote differently is retired by the 30-day gone sweep.

DO $$
DECLARE
    r          record;
    v_origin   text;
    v_path     text;
    v_query    text;
    v_template text;
    v_hash     text;
    v_origin_id uuid;
    v_endpoint_id uuid;
BEGIN
    FOR r IN
        SELECT a.id, a.tenant_id, a.name
          FROM assets a
         WHERE a.sub_type = 'discovered_url' AND a.name ~* '^https?://[^/?#]+'
    LOOP
        v_origin := regexp_replace(regexp_replace(lower(substring(r.name FROM '^(https?://[^/?#]+)')),
                        '^(https://.+):443$', '\1'), '^(http://.+):80$', '\1');
        v_path := COALESCE(NULLIF(rtrim(substring(r.name FROM '^https?://[^/?#]+(/[^?#]*)'), '/'), ''), '/');
        v_query := substring(r.name FROM '\?([^#]*)');
        v_template := left(regexp_replace(regexp_replace(v_path,
                        '/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)', '/{uuid}', 'g'),
                        '/[0-9]+(?=/|$)', '/{int}', 'g'), 2048);
        v_hash := encode(sha256(convert_to('GET' || chr(10) || v_template, 'UTF8')), 'hex');

        SELECT o.id INTO v_origin_id
          FROM assets o
         WHERE o.tenant_id = r.tenant_id AND o.name = v_origin AND o.deleted_at IS NULL
         ORDER BY (o.sub_type = 'http') DESC, o.created_at
         LIMIT 1;
        IF v_origin_id IS NULL THEN
            INSERT INTO assets (id, tenant_id, name, asset_type, sub_type)
            VALUES (uuid_generate_v7(), r.tenant_id, v_origin, 'service', 'http')
            RETURNING id INTO v_origin_id;
        END IF;

        INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash,
                                   kind, sources, first_seen_at, last_seen_at)
        VALUES (uuid_generate_v7(), r.tenant_id, v_origin_id, 'GET', v_template, v_hash,
                encode(sha256(convert_to(v_template, 'UTF8')), 'hex'), 'page', ARRAY['crawl'], now(), now())
        ON CONFLICT (tenant_id, origin_asset_id, template_hash) DO NOTHING;

        SELECT e.id INTO v_endpoint_id
          FROM web_endpoints e
         WHERE e.tenant_id = r.tenant_id AND e.origin_asset_id = v_origin_id AND e.template_hash = v_hash;

        INSERT INTO web_endpoint_params (tenant_id, endpoint_id, location, name, sources)
        SELECT DISTINCT r.tenant_id, v_endpoint_id, 'query', left(split_part(kv, '=', 1), 128), ARRAY['crawl']
          FROM unnest(string_to_array(COALESCE(v_query, ''), '&')) AS kv
         WHERE split_part(kv, '=', 1) <> ''
        ON CONFLICT DO NOTHING;

        UPDATE web_endpoints e
           SET param_count = (SELECT count(*) FROM web_endpoint_params p WHERE p.endpoint_id = e.id)
         WHERE e.id = v_endpoint_id;

        UPDATE findings SET asset_id = v_origin_id WHERE tenant_id = r.tenant_id AND asset_id = r.id;
        UPDATE exposure_events SET asset_id = v_origin_id WHERE tenant_id = r.tenant_id AND asset_id = r.id;
        DELETE FROM assets WHERE tenant_id = r.tenant_id AND id = r.id;
    END LOOP;
END $$;
