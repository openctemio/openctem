UPDATE tools
SET output_types = '{}'
WHERE tenant_id IS NULL AND name = 'dnsx-enum' AND output_types = '{domain,subdomain}';
