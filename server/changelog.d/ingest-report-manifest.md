### Added: verified commit manifest for segmented sensor reports

- The commit of a segmented sensor report may carry a manifest: each segment's SHA-256 over its decoded content, its size, its asset and finding counts, the report totals and one hash for the whole report. The server compares every value with what it received and refuses a mismatch (`409 segment-set-mismatch`, naming `hash_mismatch`, `size_mismatch`, `count_mismatch` or `report_hash_mismatch`); the report then stays uncommitted. Hello lists the feature `results_manifest`.
- Each committed report records its integrity (`single`, `manifest`, `digest_only`) and a content hash; the report status shows the integrity, and the status of an uncommitted report lists the segments the server holds, so a sensor resuming an upload sends only the missing ones.
- New counter `openctem_ingest_v2_commit_integrity_total{result}`.

### Behaviour change: coverage auto-close needs a verified report

- A segmented report committed without a manifest (older SDKs) no longer proves absence for coverage auto-close (`integrity_unverified`). Single-segment reports, which are all reports on most installs today, are unaffected.
