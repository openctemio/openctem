### Added: CVEs named only by CNA vendor/product strings match once the feed's alias dictionary maps them

- Global product aliases now record their source (`curated`, `feed`, or `observed` for tenant rows) and accept the `purl` kind (migration `software_alias_feed`).
- `ApplyFeedAliases` writes the vulnerability feed's alias dictionary (CNA vendor:product keys, deprecated CPEs, package identities → canonical product) and merges each feed-created duplicate product into its canonical product: ranges, versions, links, VEX statements and bundle keys move, and the affected versions and tenants are matched again without a re-ingest.
- Curated aliases and products always win over the feed; tenant-private products are never merged; malformed entries are skipped; a dictionary over the merge limit, or an empty one, is refused whole; feed aliases the dictionary no longer carries are removed.
- An entry that is not reviewed (learned from advisory text) folds only a product whose ranges all come from CNA names; a product with NVD/OSV ranges or no ranges is held for the operator. Package (purl) aliases must be reviewed; a package a global purl alias names resolves to that global product, ahead of the tenant's own row.
- Every fold is journaled in `software_product_merges` (folded identity, entry, moved versions, CVEs; no tenant data) so a wrong fold can be split, and folds lock the vulnfeed checkpoint so they never run beside a bundle chunk of another replica.
- New concurrent indexes for folds on populated tables: `asset_software(product_id)`, `cve_feed_products(product_id)`, and the range-condition columns of `vulnerability_affected` and `software_version_vulns`.
- The curated list folds a feed-created product with one of its alternate CPEs into the curated product.
