### Fixed: subdomain takeover exposure events name the resolved addresses ip_addresses

- The suspected-takeover event detail key `addresses` is now `ip_addresses`, the canonical property name, which keeps the property-synonym lint green.
