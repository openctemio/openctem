-- Rollback: remove extracted flat fields (original nested data preserved)
UPDATE assets SET properties = properties - 'record_type' - 'resolved_ip' - 'cname_target' - 'ttl' - 'dns_record_types' - 'resolved_ips' - 'dns_record_count'
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties IS NOT NULL;
