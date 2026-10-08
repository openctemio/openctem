-- Fold stored property synonyms into their canonical keys (one-off data fix).
--
-- The property naming convention (docs/architecture/asset-inventory-v2.md,
-- "Property names") renamed keys that broke it (mfa_enabled -> has_mfa,
-- last_used -> last_used_at, encrypted -> is_encrypted, ...) and keeps each
-- old name as a synonym in api/configs/asset-types.yaml. Every write path
-- folds synonyms (NormalizeProperties); this migration folds the rows written
-- before, so readers need only the canonical key.
--
-- Rules, the same as NormalizeProperties:
--   * scalar key: the canonical value wins; without one, the first synonym in
--     schema order moves to it unchanged (a boolean stays a boolean);
--   * list key: the string values of the synonyms are merged into the
--     canonical array without duplicates (ip keys: split on , ; and space,
--     lower-cased, non-addresses dropped);
--   * an object under a synonym name (the CTIS technical ip_address block)
--     is not a value of the key and stays.
-- Idempotent: a second run finds no synonym left.

-- The merged array of a list key: its own elements, then the synonym's
-- strings, without duplicates, in first-seen order.
CREATE FUNCTION pg_temp.fold_list_synonym(props jsonb, syn text, canon text, is_ip boolean)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $fn$
    WITH own AS (
        SELECT e AS val, n AS pos
          FROM jsonb_array_elements(
                   CASE jsonb_typeof(props -> canon)
                       WHEN 'array' THEN props -> canon
                       WHEN 'string' THEN jsonb_build_array(props -> canon)
                       ELSE '[]'::jsonb
                   END) WITH ORDINALITY AS c(e, n)
    ),
    raw AS (
        SELECT r, rn
          FROM jsonb_array_elements(
                   CASE jsonb_typeof(props -> syn)
                       WHEN 'array' THEN props -> syn
                       WHEN 'string' THEN jsonb_build_array(props -> syn)
                       ELSE '[]'::jsonb
                   END) WITH ORDINALITY AS x(r, rn)
         WHERE jsonb_typeof(r) = 'string'
    ),
    toks AS (
        SELECT CASE WHEN is_ip THEN lower(t) ELSE btrim(t) END AS tok, rn * 1000 + tn AS pos
          FROM raw,
               LATERAL regexp_split_to_table(
                   raw.r #>> '{}', CASE WHEN is_ip THEN '[,; ]+' ELSE '$^' END
               ) WITH ORDINALITY AS s(t, tn)
    ),
    theirs AS (
        SELECT to_jsonb(tok) AS val, 1000000 + pos AS pos
          FROM toks
         WHERE tok <> ''
           AND (NOT is_ip
                OR tok ~ '^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'
                OR (tok ~ '^[0-9a-f:.]+$' AND position(':' IN tok) > 0))
    ),
    merged AS (
        SELECT val, MIN(pos) AS pos
          FROM (SELECT * FROM own UNION ALL SELECT * FROM theirs) u
         GROUP BY val
    )
    SELECT (props - syn) || COALESCE(
               (SELECT jsonb_build_object(canon, jsonb_agg(val ORDER BY pos)) FROM merged),
               '{}'::jsonb)
$fn$;

DO $$
DECLARE
    p RECORD;
BEGIN
    -- Scalar keys, in schema order (ord): the first synonym present wins.
    FOR p IN
        SELECT * FROM (VALUES
            ('self_signed', 'is_self_signed', 0),
            ('tls_enabled', 'has_tls', 0),
            ('auth_required', 'is_auth_required', 0),
            ('rate_limiting', 'has_rate_limiting', 0),
            ('cors_enabled', 'has_cors', 0),
            ('uses_ssl_pinning', 'has_ssl_pinning', 0),
            ('os', 'os_name', 0),
            ('web_server', 'server', 0),
            ('edr_installed', 'has_edr', 0),
            ('last_modified', 'last_modified_at', 0),
            ('mfa_enabled', 'has_mfa', 0),
            ('rbac_enabled', 'has_rbac', 0),
            ('pod_security_enabled', 'has_pod_security', 0),
            ('network_policies', 'has_network_policies', 0),
            ('scan_on_push', 'has_scan_on_push', 0),
            ('encrypted', 'is_encrypted', 0),
            ('encryption_enabled', 'is_encrypted', 1),
            ('encryption', 'is_encrypted', 2),
            ('immutable_tags', 'has_immutable_tags', 0),
            ('archived', 'is_archived', 0),
            ('privileged', 'is_privileged', 0),
            ('last_used', 'last_used_at', 0),
            ('last_login', 'last_login_at', 0),
            ('max_session_duration', 'max_session_duration_seconds', 0),
            ('ssl_enforced', 'is_ssl_enforced', 0),
            ('versioning_enabled', 'has_versioning', 0),
            ('logging_enabled', 'has_logging', 0),
            ('dhcp_enabled', 'has_dhcp', 0),
            ('flow_logs_enabled', 'has_flow_logs', 0),
            ('publicly_accessible', 'is_public', 0),
            ('is_publicly_accessible', 'is_public', 1)
        ) AS v(syn, canon, ord)
        ORDER BY canon, ord
    LOOP
        UPDATE assets
           SET properties = CASE
                   WHEN properties ? p.canon OR jsonb_typeof(properties -> p.syn) = 'null'
                       THEN properties - p.syn
                   ELSE (properties - p.syn) || jsonb_build_object(p.canon, properties -> p.syn)
               END
         WHERE properties ? p.syn
           AND jsonb_typeof(properties -> p.syn) <> 'object';
    END LOOP;

    -- List keys.
    FOR p IN
        SELECT * FROM (VALUES
            ('ip', 'ip_addresses', true),
            ('ips', 'ip_addresses', true),
            ('ip_address', 'ip_addresses', true),
            ('resolved_ip', 'ip_addresses', true),
            ('resolved_ips', 'ip_addresses', true),
            ('addresses', 'ip_addresses', true),
            ('nameserver', 'nameservers', false),
            ('san', 'sans', false),
            ('technology', 'technologies', false)
        ) AS v(syn, canon, is_ip)
    LOOP
        UPDATE assets
           SET properties = pg_temp.fold_list_synonym(properties, p.syn, p.canon, p.is_ip)
         WHERE properties ? p.syn
           AND jsonb_typeof(properties -> p.syn) <> 'object';
    END LOOP;

    -- `fingerprint` on a certificate is its SHA-256 fingerprint. It is not a
    -- synonym (the word means other things elsewhere); fold it here once.
    UPDATE assets
       SET properties = CASE
               WHEN properties ? 'fingerprint_sha256' THEN properties - 'fingerprint'
               ELSE (properties - 'fingerprint') || jsonb_build_object('fingerprint_sha256', properties -> 'fingerprint')
           END
     WHERE asset_type = 'certificate'
       AND properties ? 'fingerprint'
       AND jsonb_typeof(properties -> 'fingerprint') = 'string';
END $$;

DROP FUNCTION pg_temp.fold_list_synonym(jsonb, text, text, boolean);
