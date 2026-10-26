### Changed: SRV records are pinned as data-only in the DNS records contract

- Tests pin that an SRV record on a domain or subdomain is accepted, kept and listed in `dns_record_types`, and that its target never becomes the asset's `cname_target` or `ip_addresses`.
