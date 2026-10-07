### Fixed: stored assets typed against their own name are corrected

- Migration 001151 retypes an `ip_address` asset whose name is a DNS name to `domain`, and a `domain`/`subdomain` asset whose name is an IP literal to `ip_address` (the rule ingest now applies). The sub-type is cleared and one system audit row (`asset.type_corrected`, with the old type) is written per change. A row whose target name already exists in the tenant is skipped with a NOTICE. The down migration is a no-op.
