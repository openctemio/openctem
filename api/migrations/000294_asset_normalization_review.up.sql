-- RFC-043 P0 (docs/rfcs/RFC-043-deduplication-and-identity.md section 10).
--
-- Until this release a new asset's name was normalized without its sub-type,
-- while lookups used the sub-type. Two kinds of stored names are wrong:
--
--   1. http_service / discovered_url assets (asset_type 'service', sub_type
--      'http' or 'discovered_url') went through the port-identifier normalizer:
--      "https://api.example.com:443" was stored as "https:::api.example.com:443".
--      Several spellings of one URL became several assets.
--   2. Cloud compute / serverless assets named by an ARN went through the DNS
--      normalizer, which cut the name at the first "/": two EC2 instances
--      became one asset named "arn:aws:ec2:<region>:<account>:instance".
--
-- The code now normalizes correctly. Existing rows are NOT renamed or merged
-- here: each is queued as a pending dedup review with the evidence, for an
-- admin to merge, rename or reject.
--
--   reason 'normalization_garbled'  several assets (garbled and/or already
--                                   canonical) are one URL: keep = the asset
--                                   already carrying the canonical name, else
--                                   the one with most findings, then earliest.
--   reason 'normalization_rename'   one garbled asset, no duplicate: rename it
--                                   to evidence.proposed_name (merge set empty).
--   reason 'normalization_truncated_arn'
--                                   an ARN cut at the resource type; the
--                                   resource ids are lost and the asset may
--                                   hold several resources' findings. Flag only.

WITH garbled AS (
    SELECT a.id, a.tenant_id, a.name, a.created_at,
           split_part(a.name, ':::', 1) AS scheme,
           split_part(substr(a.name, length(split_part(a.name, ':::', 1)) + 4), ':', 1) AS host,
           split_part(substr(a.name, length(split_part(a.name, ':::', 1)) + 4), ':', 2) AS port
    FROM assets a
    WHERE a.asset_type = 'service'
      AND a.sub_type IN ('http', 'discovered_url')
      AND a.name ~ '^[a-z][a-z0-9+.-]*:::'
),
proposed AS (
    SELECT g.id, g.tenant_id,
           g.scheme || '://' || g.host ||
           CASE WHEN g.port = '' OR (g.scheme = 'https' AND g.port = '443') OR (g.scheme = 'http' AND g.port = '80')
                THEN '' ELSE ':' || g.port END AS canonical
    FROM garbled g
    WHERE g.host <> ''
),
members AS (
    -- the garbled rows, plus an asset that already has the canonical name
    SELECT p.tenant_id, p.canonical, p.id, false AS is_canonical FROM proposed p
    UNION
    SELECT p.tenant_id, p.canonical, a.id, true
    FROM proposed p
    JOIN assets a ON a.tenant_id = p.tenant_id AND a.name = p.canonical
),
ranked AS (
    SELECT m.tenant_id, m.canonical,
           array_agg(a.id ORDER BY m.is_canonical DESC, COALESCE(fc.cnt, 0) DESC, a.created_at ASC) AS ids,
           array_agg(a.name ORDER BY m.is_canonical DESC, COALESCE(fc.cnt, 0) DESC, a.created_at ASC) AS names,
           array_agg(COALESCE(fc.cnt, 0)::int ORDER BY m.is_canonical DESC, COALESCE(fc.cnt, 0) DESC, a.created_at ASC) AS fc
    FROM members m
    JOIN assets a ON a.id = m.id
    LEFT JOIN (SELECT asset_id, COUNT(*) AS cnt FROM findings GROUP BY asset_id) fc ON fc.asset_id = a.id
    GROUP BY m.tenant_id, m.canonical
)
INSERT INTO asset_dedup_review (
    tenant_id, normalized_name, asset_type,
    keep_asset_id, keep_asset_name, keep_finding_count,
    merge_asset_ids, merge_asset_names, merge_finding_count,
    status, reason, evidence
)
SELECT r.tenant_id, r.canonical, 'service',
       r.ids[1], r.names[1], r.fc[1],
       COALESCE(r.ids[2:], '{}'), COALESCE(r.names[2:], '{}'),
       COALESCE((SELECT SUM(x) FROM unnest(r.fc[2:]) AS x), 0),
       'pending',
       CASE WHEN cardinality(r.ids) > 1 THEN 'normalization_garbled' ELSE 'normalization_rename' END,
       jsonb_build_object(
           'proposed_name', r.canonical,
           'stored_names', to_jsonb(r.names),
           'cause', 'asset name normalized without its sub-type (RFC-043 section 10)')
FROM ranked r
ON CONFLICT DO NOTHING;

INSERT INTO asset_dedup_review (
    tenant_id, normalized_name, asset_type,
    keep_asset_id, keep_asset_name, keep_finding_count,
    merge_asset_ids, merge_asset_names, merge_finding_count,
    status, reason, evidence
)
SELECT a.tenant_id, a.name, a.asset_type,
       a.id, a.name, COALESCE(fc.cnt, 0)::int,
       '{}', '{}', 0,
       'pending', 'normalization_truncated_arn',
       jsonb_build_object(
           'stored_name', a.name,
           'cause', 'ARN cut at the first "/" by the DNS normalizer; resource ids are lost and this asset may hold findings of several resources (RFC-043 section 10)')
FROM assets a
LEFT JOIN (SELECT asset_id, COUNT(*) AS cnt FROM findings GROUP BY asset_id) fc ON fc.asset_id = a.id
WHERE a.asset_type = 'host'
  AND a.name ~ '^arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-z0-9-]+$'
ON CONFLICT DO NOTHING;
