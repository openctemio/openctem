-- Normalise stored asset properties to the property schema (RFC-042 §6.3.9,
-- docs/rfcs/RFC-042-asset-inventory-v2.md).
--
-- One concept was stored under several keys. Every write path now folds a
-- synonym into its canonical key (asset.NormalizeProperties); this does the
-- same for the rows written before:
--
--   - ip, ips, a plain ip_address string, resolved_ip, resolved_ips and
--     addresses fold into ip_addresses (a list of addresses in canonical
--     form; a comma-separated string is split, a value that is not an
--     address is dropped). An object under ip_address (the CTIS technical
--     block) stays; only its address joins the list. An IP address asset
--     does not list its own address;
--   - nameserver -> nameservers, technology -> technologies, san -> sans;
--   - a key only other classes may hold is removed: a port (with its
--     protocol and transport), an HTTP status, content length or type, or
--     a response time on a domain, host or IP address, a banner outside a
--     service. Ingest stores the next sighting of such a port as the
--     asset's host:port service.
--
-- The lists below are the registry's at this version
-- (api/configs/asset-types.yaml). Every changed row's previous properties
-- are kept in asset_properties_pre_001181 for the down migration; names,
-- ids and updated_at are not touched. No audit or history rows are written.

CREATE TABLE asset_properties_pre_001181 (
    asset_id   uuid PRIMARY KEY REFERENCES assets (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL,
    properties jsonb NOT NULL,
    saved_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE asset_properties_pre_001181 IS
    'Asset properties before migration 001181 normalised them (RFC-042 6.3.9); read only by its down migration.';

-- mig001181_fold appends the values v holds to acc, without duplicates:
-- strings and the strings of a list; for an address key also the address
-- of an object, every value split on , ; and space and kept only when it
-- is one address (canonical form).
CREATE FUNCTION mig001181_fold(acc text[], v jsonb, as_ip boolean)
RETURNS text[] LANGUAGE plpgsql IMMUTABLE AS $fn$
DECLARE
    item text;
    part text;
    addr inet;
BEGIN
    IF v IS NULL THEN
        RETURN acc;
    END IF;
    FOR item IN
        SELECT v #>> '{}' WHERE jsonb_typeof(v) = 'string'
        UNION ALL
        SELECT e #>> '{}'
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v) = 'array' THEN v ELSE '[]'::jsonb END) AS e
        WHERE jsonb_typeof(e) = 'string'
        UNION ALL
        SELECT v ->> 'address'
        WHERE as_ip AND jsonb_typeof(v) = 'object' AND jsonb_typeof(v -> 'address') = 'string'
    LOOP
        IF NOT as_ip THEN
            part := btrim(item);
            IF part <> '' AND NOT (part = ANY (acc)) THEN
                acc := acc || part;
            END IF;
            CONTINUE;
        END IF;
        FOREACH part IN ARRAY regexp_split_to_array(item, '[,; ]+') LOOP
            part := btrim(part);
            CONTINUE WHEN part = '' OR strpos(part, '/') > 0;
            BEGIN
                addr := part::inet;
            EXCEPTION WHEN others THEN
                CONTINUE;
            END;
            CONTINUE WHEN masklen(addr) <> CASE family(addr) WHEN 4 THEN 32 ELSE 128 END;
            part := host(addr);
            IF NOT (part = ANY (acc)) THEN
                acc := acc || part;
            END IF;
        END LOOP;
    END LOOP;
    RETURN acc;
END
$fn$;

-- mig001181_normalize returns p folded and without misplaced keys, for an
-- asset of class cls named own.
CREATE FUNCTION mig001181_normalize(p jsonb, cls text, own text)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $fn$
DECLARE
    f      record;
    m      record;
    vals   text[];
    keep   jsonb;
    syn    text;
    v      jsonb;
    self   text[];
BEGIN
    IF p IS NULL OR jsonb_typeof(p) <> 'object' THEN
        RETURN p;
    END IF;

    FOR f IN
        SELECT * FROM (VALUES
            ('ip_addresses', ARRAY['ip', 'ips', 'ip_address', 'resolved_ip', 'resolved_ips', 'addresses'], true),
            ('nameservers', ARRAY['nameserver'], false),
            ('technologies', ARRAY['technology'], false),
            ('sans', ARRAY['san'], false)
        ) AS t (key, synonyms, is_ip)
    LOOP
        CONTINUE WHEN NOT (p ? f.key OR p ?| f.synonyms);
        -- Non-string elements of the canonical list are kept as they are.
        keep := COALESCE((
            SELECT jsonb_agg(e)
            FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p -> f.key) = 'array' THEN p -> f.key ELSE '[]'::jsonb END) AS e
            WHERE jsonb_typeof(e) NOT IN ('string', 'null')
        ), '[]'::jsonb);
        vals := mig001181_fold('{}'::text[], p -> f.key, f.is_ip);
        FOREACH syn IN ARRAY f.synonyms LOOP
            v := p -> syn;
            CONTINUE WHEN v IS NULL;
            vals := mig001181_fold(vals, v, f.is_ip);
            IF jsonb_typeof(v) <> 'object' THEN
                p := p - syn;
            END IF;
        END LOOP;
        IF f.is_ip AND cls = 'ip_address' THEN
            self := mig001181_fold('{}'::text[], to_jsonb(own), true);
            IF cardinality(self) = 1 THEN
                vals := array_remove(vals, self[1]);
            END IF;
        END IF;
        IF cardinality(vals) = 0 AND jsonb_array_length(keep) = 0 THEN
            p := p - f.key;
        ELSE
            p := jsonb_set(p, ARRAY[f.key], keep || to_jsonb(vals));
        END IF;
    END LOOP;

    FOR m IN
        SELECT * FROM (VALUES
            ('port', ARRAY['service', 'data_store', 'application', 'web_endpoint']),
            ('status_code', ARRAY['service', 'web_endpoint', 'application']),
            ('content_length', ARRAY['service', 'web_endpoint', 'application']),
            ('content_type', ARRAY['service', 'web_endpoint', 'application']),
            ('response_time_ms', ARRAY['service', 'web_endpoint', 'application']),
            ('banner', ARRAY['service'])
        ) AS t (key, classes)
    LOOP
        IF p ? m.key AND cls IS NOT NULL AND NOT (cls = ANY (m.classes)) THEN
            p := p - m.key;
            -- The protocol and transport of a misplaced port go with it.
            IF m.key = 'port' THEN
                p := p - 'protocol' - 'transport';
            END IF;
        END IF;
    END LOOP;
    RETURN p;
END
$fn$;

INSERT INTO asset_properties_pre_001181 (asset_id, tenant_id, properties)
SELECT a.id, a.tenant_id, a.properties
FROM assets a
WHERE a.properties ?| ARRAY['ip', 'ips', 'ip_address', 'resolved_ip', 'resolved_ips', 'addresses', 'ip_addresses',
                            'nameserver', 'nameservers', 'technology', 'technologies', 'san', 'sans',
                            'port', 'status_code', 'content_length', 'content_type', 'response_time_ms', 'banner']
  AND mig001181_normalize(a.properties, a.asset_class, a.name) IS DISTINCT FROM a.properties;

-- A data fix, not an edit: updated_at keeps its value.
ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
UPDATE assets a
SET properties = mig001181_normalize(a.properties, a.asset_class, a.name)
FROM asset_properties_pre_001181 b
WHERE b.asset_id = a.id AND b.tenant_id = a.tenant_id;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

DROP FUNCTION mig001181_normalize(jsonb, text, text);
DROP FUNCTION mig001181_fold(text[], jsonb, boolean);
