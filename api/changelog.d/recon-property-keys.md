### Fixed: recon properties belong to their asset types

- Ingest warned "report asset properties outside the asset type schema" for
  keys the recon converter writes. They are now part of the schema of the
  asset they land on: `open_port_count` (addresses), `dns_record_count`
  (domains and subdomains), `discovery_method` (subdomains: the passive
  source that reported the name), `fingerprint` and `is_host_mismatch`
  (certificates; `host_mismatch` folds into it), `cdn_type`, `favicon_mmh3`
  and `tls_fingerprint` (web origins). They become filterable and shown
  with labels in English and Vietnamese.
