### Changed: every remaining API read in the web console is cached under its URL

- Threat intelligence (sync status, EPSS, KEV, CVE enrichment), asset (full
  view, repository, tags) and exposure (detail, history) reads share the cache
  with every other reader of the same endpoint, and `mutate(url)` reaches them.
