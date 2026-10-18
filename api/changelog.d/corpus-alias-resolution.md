### Added: CVEs named only by CNA vendor/product strings match once the feed's alias dictionary maps them

- Global product aliases now record their source (`curated`, `feed`, or `observed` for tenant rows) and accept the `purl` kind (migration `software_alias_feed`).
- `ApplyFeedAliases` writes the vulnerability feed's alias dictionary (CNA vendor:product keys, deprecated CPEs, package identities → canonical product) and merges each feed-created duplicate product into its canonical product: ranges, versions, links, VEX statements and bundle keys move, and the affected versions and tenants are matched again without a re-ingest.
- Curated aliases and products always win over the feed; tenant-private products are never merged; malformed entries are skipped; a dictionary over the merge limit is refused whole. A package a global purl alias names resolves to that global product, ahead of the tenant's own row.
- The curated list folds a feed-created product with one of its alternate CPEs into the curated product.
