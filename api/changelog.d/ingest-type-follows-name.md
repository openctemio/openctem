### Fixed: an ingested asset's type no longer contradicts its name

- A DNS name reported as `ip_address` (for example a recon tool's target type) was stored and shown as an IP address. Ingest now stores it as a `domain`, and an IP literal reported as `domain` or `subdomain` as an `ip_address`. Other types are left as reported. Rows already stored with the wrong type are not rewritten; re-ingesting the asset does not move them either, so correct them by hand or delete and rediscover.
