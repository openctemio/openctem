-- Restore the pre-000234 seeded pairs. A remapped row goes back only when its
-- old pair is free; a removed duplicate is re-created with its seeded priority.
-- (A corrected pair an administrator created after 000234 is indistinguishable
-- from a remapped one and is also moved back.)

-- old_priority NULL: 000234 kept the row's priority.
WITH fix (old_target, old_asset, new_target, new_asset, old_priority) AS (VALUES
    ('ip',    'ip',                  'ip',            'ip_address',    NULL::int),
    ('host',  'ip',                  'host',          'ip_address',    NULL),
    ('cloud', 'cloud_account',       'cloud_account', 'cloud_account', 10),
    ('cloud', 'compute',             'compute',       'compute',       20),
    ('cloud', 'storage',             'storage',       'storage',       30),
    ('cloud', 's3_bucket',           'storage',       's3_bucket',     50),
    ('cloud', 'serverless_function', 'serverless',    'serverless',    40)
)
UPDATE target_asset_type_mappings m
SET target_type = f.old_target, asset_type = f.old_asset,
    priority = COALESCE(f.old_priority, m.priority), updated_at = NOW()
FROM fix f
WHERE m.target_type = f.new_target AND m.asset_type = f.new_asset
  AND NOT EXISTS (
      SELECT 1 FROM target_asset_type_mappings x
      WHERE x.target_type = f.old_target AND x.asset_type = f.old_asset
  );

INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('ip',    'server', 30),
    ('host',  'server', 20),
    ('cloud', 'vpc',    60)
ON CONFLICT (target_type, asset_type) DO NOTHING;
