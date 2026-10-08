-- Promote the CTIS technical blocks to flat property keys (one-off data fix).
--
-- Properties are flat (RFC-042 §6.3.10, architecture page "Property names"):
-- ingest, REST and import now move a technical block's facts
-- (properties.domain.*, ip_address.*, service.*, certificate.*) to the
-- stored type's keys and drop the block (asset.PromoteTechnicalBlocks).
-- This migration does the same to the rows written before:
--   * a domain's or subdomain's DNS records give dns_record_types, the first
--     CNAME target and the A/AAAA addresses (merged into ip_addresses);
--   * each block field fills the key the mapping below names for the row's
--     (type, sub_type), generated from the registry; a flat value already
--     there wins; empty values are skipped;
--   * the block objects are removed. A field the type has no key for is
--     dropped with them (a service's certificate is a certificate asset, a
--     host's ports are services).
-- Idempotent: a second run finds no block.

CREATE TEMP TABLE block_promotion (asset_type text, sub_type text, block text, field text, target text);
INSERT INTO block_promotion VALUES
    ('application', '', 'service', 'name', 'server'),
    ('application', 'api', 'service', 'name', 'server'),
    ('application', 'api', 'service', 'version', 'version'),
    ('application', 'mobile_app', 'service', 'name', 'server'),
    ('application', 'mobile_app', 'service', 'version', 'version'),
    ('application', 'website', 'service', 'name', 'server'),
    ('application', 'website', 'service', 'tls_version', 'tls_version'),
    ('certificate', '', 'certificate', 'expired', 'is_expired'),
    ('certificate', '', 'certificate', 'fingerprint', 'fingerprint_sha256'),
    ('certificate', '', 'certificate', 'issuer_cn', 'issuer_cn'),
    ('certificate', '', 'certificate', 'issuer_org', 'issuer_org'),
    ('certificate', '', 'certificate', 'key_algorithm', 'key_algorithm'),
    ('certificate', '', 'certificate', 'key_size', 'key_size'),
    ('certificate', '', 'certificate', 'not_after', 'not_after'),
    ('certificate', '', 'certificate', 'not_before', 'not_before'),
    ('certificate', '', 'certificate', 'sans', 'sans'),
    ('certificate', '', 'certificate', 'self_signed', 'is_self_signed'),
    ('certificate', '', 'certificate', 'serial_number', 'serial_number'),
    ('certificate', '', 'certificate', 'signature_algorithm', 'signature_algorithm'),
    ('certificate', '', 'certificate', 'subject_cn', 'subject_cn'),
    ('domain', '', 'domain', 'dns_records', 'dns_records'),
    ('domain', '', 'domain', 'expires_at', 'expires_at'),
    ('domain', '', 'domain', 'nameservers', 'nameservers'),
    ('domain', '', 'domain', 'registered_at', 'registered_at'),
    ('domain', '', 'domain', 'registrar', 'registrar'),
    ('domain', '', 'domain', 'whois', 'whois'),
    ('host', '', 'ip_address', 'hostname', 'hostname'),
    ('host', 'compute', 'ip_address', 'hostname', 'hostname'),
    ('host', 'serverless', 'ip_address', 'hostname', 'hostname'),
    ('host', 'workstation', 'ip_address', 'hostname', 'hostname'),
    ('ip_address', '', 'ip_address', 'asn', 'asn'),
    ('ip_address', '', 'ip_address', 'asn_org', 'asn_org'),
    ('ip_address', '', 'ip_address', 'city', 'city'),
    ('ip_address', '', 'ip_address', 'country', 'country'),
    ('ip_address', '', 'ip_address', 'geolocation', 'geolocation'),
    ('ip_address', '', 'ip_address', 'hostname', 'hostname'),
    ('ip_address', '', 'ip_address', 'ports', 'ports'),
    ('ip_address', '', 'ip_address', 'version', 'version'),
    ('service', '', 'service', 'auth_required', 'is_auth_required'),
    ('service', '', 'service', 'banner', 'banner'),
    ('service', '', 'service', 'cpe', 'cpe'),
    ('service', '', 'service', 'port', 'port'),
    ('service', '', 'service', 'product', 'product'),
    ('service', '', 'service', 'protocol', 'protocol'),
    ('service', '', 'service', 'state', 'state'),
    ('service', '', 'service', 'tls', 'has_tls'),
    ('service', '', 'service', 'tls_version', 'tls_version'),
    ('service', '', 'service', 'transport', 'transport'),
    ('service', '', 'service', 'version', 'version'),
    ('service', 'http', 'service', 'auth_required', 'is_auth_required'),
    ('service', 'http', 'service', 'banner', 'banner'),
    ('service', 'http', 'service', 'cpe', 'cpe'),
    ('service', 'http', 'service', 'name', 'server'),
    ('service', 'http', 'service', 'port', 'port'),
    ('service', 'http', 'service', 'product', 'product'),
    ('service', 'http', 'service', 'protocol', 'protocol'),
    ('service', 'http', 'service', 'state', 'state'),
    ('service', 'http', 'service', 'tls', 'has_tls'),
    ('service', 'http', 'service', 'tls_version', 'tls_version'),
    ('service', 'http', 'service', 'transport', 'transport'),
    ('service', 'http', 'service', 'version', 'version'),
    ('service', 'open_port', 'service', 'auth_required', 'is_auth_required'),
    ('service', 'open_port', 'service', 'banner', 'banner'),
    ('service', 'open_port', 'service', 'cpe', 'cpe'),
    ('service', 'open_port', 'service', 'name', 'service'),
    ('service', 'open_port', 'service', 'port', 'port'),
    ('service', 'open_port', 'service', 'product', 'product'),
    ('service', 'open_port', 'service', 'protocol', 'protocol'),
    ('service', 'open_port', 'service', 'state', 'state'),
    ('service', 'open_port', 'service', 'tls', 'has_tls'),
    ('service', 'open_port', 'service', 'tls_version', 'tls_version'),
    ('service', 'open_port', 'service', 'transport', 'transport'),
    ('service', 'open_port', 'service', 'version', 'version'),
    ('subdomain', '', 'domain', 'dns_records', 'dns_records')
;

-- DNS summary of a name, from its records (class domain: domain, subdomain).
UPDATE assets a
   SET properties = a.properties
       || CASE WHEN a.properties ? 'dns_record_types' OR d.types IS NULL THEN '{}'::jsonb
               ELSE jsonb_build_object('dns_record_types', d.types) END
       || CASE WHEN a.properties ? 'cname_target' OR d.cname IS NULL THEN '{}'::jsonb
               ELSE jsonb_build_object('cname_target', d.cname) END
       || CASE WHEN d.addrs IS NULL THEN '{}'::jsonb
               ELSE jsonb_build_object('ip_addresses', d.addrs) END
  FROM (
        SELECT x.id,
               (SELECT string_agg(t, ', ' ORDER BY pos)
                  FROM (SELECT upper(btrim(r ->> 'type')) AS t, MIN(n) AS pos
                          FROM jsonb_array_elements(x.recs) WITH ORDINALITY AS e(r, n)
                         WHERE btrim(coalesce(r ->> 'type', '')) <> ''
                         GROUP BY 1) ty) AS types,
               (SELECT rtrim(btrim(r ->> 'value'), '.')
                  FROM jsonb_array_elements(x.recs) WITH ORDINALITY AS e(r, n)
                 WHERE upper(r ->> 'type') = 'CNAME' AND btrim(coalesce(r ->> 'value', '')) <> ''
                 ORDER BY n LIMIT 1) AS cname,
               (SELECT jsonb_agg(v ORDER BY pos)
                  FROM (SELECT v, MIN(pos) AS pos
                          FROM (SELECT e AS v, n AS pos
                                  FROM jsonb_array_elements(
                                           CASE jsonb_typeof(x.props -> 'ip_addresses')
                                               WHEN 'array' THEN x.props -> 'ip_addresses'
                                               ELSE '[]'::jsonb END) WITH ORDINALITY AS c(e, n)
                                UNION ALL
                                SELECT to_jsonb(lower(btrim(r ->> 'value'))), 100000 + n
                                  FROM jsonb_array_elements(x.recs) WITH ORDINALITY AS e(r, n)
                                 WHERE upper(r ->> 'type') IN ('A', 'AAAA')
                                   AND (lower(btrim(r ->> 'value')) ~ '^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'
                                        OR (lower(btrim(r ->> 'value')) ~ '^[0-9a-f:.]+$' AND position(':' IN r ->> 'value') > 0))
                               ) u
                         GROUP BY v) m
                HAVING COUNT(*) > 0) AS addrs
          FROM (SELECT id, properties AS props, properties -> 'domain' -> 'dns_records' AS recs
                  FROM assets
                 WHERE asset_type IN ('domain', 'subdomain')
                   AND jsonb_typeof(properties -> 'domain') = 'object'
                   AND jsonb_typeof(properties -> 'domain' -> 'dns_records') = 'array') x
       ) d
 WHERE a.id = d.id;

-- Block fields to flat keys (the first block in domain, ip_address, service,
-- certificate order wins a key two blocks fill), then the blocks go.
UPDATE assets a
   SET properties = (a.properties - ARRAY(
                         SELECT b FROM unnest(ARRAY['domain', 'ip_address', 'service', 'certificate']) AS b
                          WHERE jsonb_typeof(a.properties -> b) = 'object'))
                    || COALESCE((
                        SELECT jsonb_object_agg(f.target, f.v)
                          FROM (SELECT DISTINCT ON (p.target) p.target, a.properties -> p.block -> p.field AS v
                                  FROM block_promotion p
                                 WHERE p.asset_type = a.asset_type
                                   AND p.sub_type = coalesce(a.sub_type, '')
                                   AND jsonb_typeof(a.properties -> p.block) = 'object'
                                   -- the key is free, or holds a block that goes
                                   -- (an open port's `service` name replaces the block)
                                   AND (NOT a.properties ? p.target
                                        OR (p.target IN ('domain', 'ip_address', 'service', 'certificate')
                                            AND jsonb_typeof(a.properties -> p.target) = 'object'))
                                   AND jsonb_typeof(a.properties -> p.block -> p.field) <> 'null'
                                   AND (a.properties -> p.block -> p.field) NOT IN ('""'::jsonb, '[]'::jsonb, '{}'::jsonb)
                                 ORDER BY p.target, array_position(ARRAY['domain', 'ip_address', 'service', 'certificate'], p.block), p.field
                               ) f), '{}'::jsonb)
 WHERE jsonb_typeof(a.properties -> 'domain') = 'object'
    OR jsonb_typeof(a.properties -> 'ip_address') = 'object'
    OR jsonb_typeof(a.properties -> 'service') = 'object'
    OR jsonb_typeof(a.properties -> 'certificate') = 'object';

DROP TABLE block_promotion;
