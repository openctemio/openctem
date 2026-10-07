ALTER TABLE web_endpoints DROP COLUMN IF EXISTS exclusion_id;

ALTER TABLE scope_exclusions
    DROP CONSTRAINT IF EXISTS chk_scope_exclusion_methods,
    DROP CONSTRAINT IF EXISTS chk_scope_exclusion_path_rule,
    DROP CONSTRAINT IF EXISTS chk_scope_exclusion_testing;

-- Path rules back to the old wildcard pattern ("*/admin/debug/*").
UPDATE scope_exclusions
   SET pattern = left(rtrim(pattern, '/') || '/*', 500)
 WHERE exclusion_type = 'path' AND path_prefix IS NOT NULL;

ALTER TABLE scope_exclusions
    DROP COLUMN IF EXISTS testing_changed_at,
    DROP COLUMN IF EXISTS testing_changed_by,
    DROP COLUMN IF EXISTS testing_until,
    DROP COLUMN IF EXISTS testing,
    DROP COLUMN IF EXISTS methods,
    DROP COLUMN IF EXISTS path_prefix;
