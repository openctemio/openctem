ALTER TABLE verified_domains
    DROP CONSTRAINT IF EXISTS chk_verified_domains_join_role,
    DROP CONSTRAINT IF EXISTS chk_verified_domains_join_policy,
    DROP COLUMN IF EXISTS capture_notified_at,
    DROP COLUMN IF EXISTS include_subdomains,
    DROP COLUMN IF EXISTS block_new_workspaces,
    DROP COLUMN IF EXISTS sso_required,
    DROP COLUMN IF EXISTS discoverable,
    DROP COLUMN IF EXISTS join_role,
    DROP COLUMN IF EXISTS join_policy;
