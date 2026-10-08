-- Web endpoints for the discovered-URL assets that v0.8.0 and older stored
-- under a garbled name (docs/rfcs/RFC-056-web-attack-surface.md WS2;
-- RFC-043 section 10).
--
-- Up to v0.8.0 a new asset's name was normalized without its sub-type, so
-- every service/discovered_url asset, from a crawler report or from the API,
-- went through the port-identifier normalizer: "/" became ":" and the name
-- was lower-cased, "https://Shop.example.com/cart/Checkout?step=2" was stored
-- as "https:::shop.example.com:cart:checkout?step=2". Migration 001288 turns
-- discovered-URL assets into endpoints only when the name starts with
-- "http(s)://", so on a database upgraded from v0.8.0 it converted none of
-- them: they stayed in the inventory as service/discovered_url assets that
-- ingest no longer writes or updates. This migration converts them the same
-- way:
--
--   1. the URL is read back from the stored name: the scheme, the host (an
--      IPv6 host keeps its brackets), then the ":"-separated segments as the
--      path, up to the first "?" (or "#"). The first segment is the port
--      when it is a number and either the origin is already an asset with
--      that port (canonical "https://host:8443" or garbled
--      "https:::host:8443") or it is a common web port; otherwise it is the
--      first path segment ("/2024/report"). The path stays lower-case: the
--      original case is lost; the next crawl writes the real template and
--      the 30-day gone sweep retires this one;
--   2. the origin (scheme://host[:port], default port dropped) is the
--      tenant's live asset with that canonical name or, failing that, its
--      garbled http_service name (so the endpoints and findings land on the
--      asset that already holds the service's findings); with neither, a
--      service/http asset is created with the canonical name. A URL whose
--      origin name belongs only to a deleted asset is left as it is;
--   3. the URL becomes a GET endpoint under its origin with its query
--      parameter NAMES (never values), integer and UUID segments templated,
--      like 001288;
--   4. findings and exposure events move to the origin, pending duplicate
--      reviews that name the URL asset are removed (as the asset delete
--      does), and the URL asset is deleted (its other references cascade).
--
-- A service/http asset stored under a garbled name ("https:::host") is not
-- renamed here: migration 000294 queued it for review, and the upgrade guide
-- lists it (api/docs/operations/upgrade-v0.8-to-v0.9.md).
--
-- Every row is read and written inside its own tenant. Small on every known
-- deployment, so one row at a time. No audit rows from SQL (the audit chain
-- is extended only by the application); each conversion is a NOTICE.

DO $$
DECLARE
    r            record;
    v_scheme     text;
    v_rest       text;
    v_hostpath   text;
    v_query      text;
    v_host       text;
    v_tail       text;
    v_segs       text[];
    v_port       text;
    v_origin     text;
    v_origin_g   text;
    v_path       text;
    v_template   text;
    v_hash       text;
    v_origin_id  uuid;
    v_origin_del timestamptz;
    v_endpoint_id uuid;
    v_converted  int := 0;
    v_skipped    int := 0;
BEGIN
    FOR r IN
        SELECT a.id, a.tenant_id, a.name
          FROM assets a
         WHERE a.asset_type = 'service' AND a.sub_type = 'discovered_url'
           AND a.name ~ '^https?:::.'
         ORDER BY a.tenant_id, a.created_at, a.id
    LOOP
        v_scheme := substring(r.name FROM '^(https?):::');
        v_rest := substring(r.name FROM '^https?:::(.*)$');
        v_rest := split_part(v_rest, '#', 1);
        v_hostpath := split_part(v_rest, '?', 1);
        v_query := CASE WHEN position('?' IN v_rest) > 0 THEN substr(v_rest, position('?' IN v_rest) + 1) END;

        IF left(v_hostpath, 1) = '[' THEN
            v_host := substring(v_hostpath FROM '^(\[[^]]*\])');
            v_tail := substr(v_hostpath, length(COALESCE(v_host, '')) + 1);
        ELSE
            v_host := split_part(v_hostpath, ':', 1);
            v_tail := substr(v_hostpath, length(v_host) + 1);
        END IF;
        IF v_host IS NULL OR v_host = '' OR v_host = '[]' THEN
            RAISE NOTICE '001307: % (%): no host in the stored name, left as it is', r.id, r.name;
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
        v_tail := regexp_replace(v_tail, '^:', '');
        v_segs := CASE WHEN v_tail = '' THEN ARRAY[]::text[] ELSE string_to_array(v_tail, ':') END;

        v_port := NULL;
        IF cardinality(v_segs) > 0 AND v_segs[1] ~ '^[0-9]{1,5}$' AND v_segs[1]::int BETWEEN 1 AND 65535 AND (
               v_segs[1] IN ('80', '443', '8080', '8443', '8000', '8008', '8081', '8888', '9443', '4443')
            OR EXISTS (SELECT 1 FROM assets o
                        WHERE o.tenant_id = r.tenant_id
                          AND o.name IN (v_scheme || '://' || v_host || ':' || v_segs[1],
                                         v_scheme || ':::' || v_host || ':' || v_segs[1])))
        THEN
            v_port := v_segs[1];
            v_segs := v_segs[2:];
        END IF;

        v_origin := v_scheme || '://' || v_host ||
            CASE WHEN v_port IS NULL OR (v_scheme = 'https' AND v_port = '443') OR (v_scheme = 'http' AND v_port = '80')
                 THEN '' ELSE ':' || v_port END;
        v_origin_g := v_scheme || ':::' || v_host || COALESCE(':' || v_port, '');

        v_path := COALESCE(NULLIF(rtrim('/' || array_to_string(v_segs, '/'), '/'), ''), '/');
        v_template := left(regexp_replace(regexp_replace(v_path,
                        '/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)', '/{uuid}', 'g'),
                        '/[0-9]+(?=/|$)', '/{int}', 'g'), 2048);
        v_hash := encode(sha256(convert_to('GET' || chr(10) || v_template, 'UTF8')), 'hex');

        v_origin_id := NULL;
        v_origin_del := NULL;
        SELECT o.id, o.deleted_at INTO v_origin_id, v_origin_del
          FROM assets o
         WHERE o.tenant_id = r.tenant_id
           AND o.id <> r.id
           AND (o.name = v_origin OR (o.name = v_origin_g AND o.asset_type = 'service' AND o.sub_type = 'http'))
         ORDER BY (o.deleted_at IS NULL) DESC, (o.name = v_origin) DESC, (o.sub_type = 'http') DESC, o.created_at
         LIMIT 1;
        IF v_origin_id IS NOT NULL AND v_origin_del IS NOT NULL THEN
            RAISE NOTICE '001307: % (%): origin % is a deleted asset, left as it is', r.id, r.name, v_origin;
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
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
         WHERE e.tenant_id = r.tenant_id AND e.id = v_endpoint_id;

        UPDATE findings SET asset_id = v_origin_id WHERE tenant_id = r.tenant_id AND asset_id = r.id;
        UPDATE exposure_events SET asset_id = v_origin_id WHERE tenant_id = r.tenant_id AND asset_id = r.id;
        DELETE FROM asset_dedup_review
         WHERE tenant_id = r.tenant_id AND status = 'pending'
           AND (keep_asset_id = r.id OR r.id = ANY (merge_asset_ids));
        DELETE FROM assets WHERE tenant_id = r.tenant_id AND id = r.id;

        RAISE NOTICE '001307: % (%) -> GET % under %', r.id, r.name, v_template, v_origin;
        v_converted := v_converted + 1;
    END LOOP;
    RAISE NOTICE '001307: % discovered-URL assets converted to web endpoints, % left as they are', v_converted, v_skipped;
END $$;
