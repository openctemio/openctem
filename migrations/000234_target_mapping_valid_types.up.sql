-- Target mappings: bring the seeded rows in line with the values the API accepts.
--
-- 000031 seeded target type 'cloud', and 000060 renamed asset types to the
-- asset_types catalogue codes 'ip' and 'serverless_function'. None of these
-- is accepted by POST /api/v1/admin/target-mappings (tool.ValidTargetTypes,
-- asset.AssetType.IsValid), and 'ip' is not what assets store: IP assets are
-- 'ip_address', so the 'ip'/'host' targets mapped to no real asset. The
-- console showed rows it could not have created and cannot fix.
--
-- Decision: map each stale row to the current value when that pair does not
-- exist yet (keeps its id, description and active flag; a row that becomes the
-- first mapping of its target type gets the primary priority 10); a row whose
-- corrected pair already exists is a duplicate and is removed.
--
--   ip    -> ip                   =>  ip    -> ip_address
--   host  -> ip                   =>  host  -> ip_address
--   ip    -> server               =>  duplicate of ip -> host     (removed)
--   host  -> server               =>  duplicate of host -> host   (removed)
--   cloud -> cloud_account        =>  cloud_account -> cloud_account
--   cloud -> compute              =>  compute -> compute
--   cloud -> storage              =>  storage -> storage
--   cloud -> s3_bucket            =>  storage -> s3_bucket
--   cloud -> serverless_function  =>  serverless -> serverless
--   cloud -> vpc                  =>  duplicate of network -> vpc (removed)
--
-- 'cloud' was split into cloud_account/compute/storage/serverless in the
-- accepted target types; no built-in tool declares 'cloud'.

-- Each statement carries the mapping table inline (no temp table), so the file
-- behaves the same whether it runs in one transaction (golang-migrate) or
-- statement by statement (psql, scripts/check-sql-schema.sh).

-- Remap where the corrected pair is free. new_priority NULL keeps the row's.
WITH fix (old_target, old_asset, new_target, new_asset, new_priority) AS (VALUES
    ('ip',    'ip',                  'ip',            'ip_address',    NULL::int),
    ('host',  'ip',                  'host',          'ip_address',    NULL),
    ('ip',    'server',              'ip',            'host',          NULL),
    ('host',  'server',              'host',          'host',          NULL),
    ('cloud', 'cloud_account',       'cloud_account', 'cloud_account', 10),
    ('cloud', 'compute',             'compute',       'compute',       10),
    ('cloud', 'storage',             'storage',       'storage',       10),
    ('cloud', 's3_bucket',           'storage',       's3_bucket',     20),
    ('cloud', 'serverless_function', 'serverless',    'serverless',    10),
    ('cloud', 'vpc',                 'network',       'vpc',           NULL)
)
UPDATE target_asset_type_mappings m
SET target_type = f.new_target, asset_type = f.new_asset,
    priority = COALESCE(f.new_priority, m.priority), updated_at = NOW()
FROM fix f
WHERE m.target_type = f.old_target AND m.asset_type = f.old_asset
  AND NOT EXISTS (
      SELECT 1 FROM target_asset_type_mappings x
      WHERE x.target_type = f.new_target AND x.asset_type = f.new_asset
  );

-- What is left already has its corrected pair: a duplicate.
DELETE FROM target_asset_type_mappings m
WHERE (m.target_type, m.asset_type) IN (VALUES
    ('ip', 'ip'), ('host', 'ip'), ('ip', 'server'), ('host', 'server'),
    ('cloud', 'cloud_account'), ('cloud', 'compute'), ('cloud', 'storage'),
    ('cloud', 's3_bucket'), ('cloud', 'serverless_function'), ('cloud', 'vpc')
);
