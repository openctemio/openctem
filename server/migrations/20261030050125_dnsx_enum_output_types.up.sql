-- The stage catalog lists enumerate.subdomains@1 now, so the platform dnsx-enum
-- row records what the tool produces, like every other catalog tool (a test
-- keeps the row and pkg/domain/stage equal). The row was added with an empty
-- output_types; only that empty value is replaced.
UPDATE tools
SET output_types = '{domain,subdomain}'
WHERE tenant_id IS NULL AND name = 'dnsx-enum' AND output_types = '{}';
