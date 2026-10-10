### Added: chunked vulnerability feed import with a resumable checkpoint

- The vulnerability bundle importer reads bundle format v2 through the sdk-go transfer layer when the release (or `VULNFEED_BUNDLE_DIR`) serves it: retries, Range resume, mirror fall-back (`VULNFEED_MIRRORS`, https only), a verified chunk cache, and each chunk applied in its own transaction with the `feed_checkpoints` row, so a crash resumes at the next chunk. The v1 reader stays the fallback for this release and shares the applied sequence and key-set version.
- Every check is kept: pinned root, key-set version, sequence newer than applied, delta on its base, expiry, size caps, per-record validation, and ranges must name CVEs and products of the same bundle.
- CVE records and ranges carry the bundle sequence (migration `cve_corpus_feed_sequence`: `feed_sequence` and `range_key` columns, table `cve_feed_products`, platform-wide, no tenant data). Replaced ranges are removed when the bundle finishes, where the removal guard now runs.
- The inventory matcher re-evaluates only CVEs whose record or ranges changed.
