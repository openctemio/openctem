### Changed: vulnerability matching reads product ranges through the vulnerability catalog reader

- New `vulncatalog.Reader` (RFC-143): one read seam for the public vulnerability catalog (product ranges, global products and aliases, CVE facts and records, KEV, EPSS, advisory id aliases), with a Postgres implementation over today's tables and a disabled implementation whose every read fails with `vulncatalog.ErrUnavailable`. Matching and version retests read product ranges through it; results are unchanged.
- "Catalog unavailable" means unknown, never "no ranges": a matcher run that cannot read ranges stops before it replaces version results or reconciles any organization, so it closes no finding.
- The reader reads global rows only: a tenant-private product or alias is never returned.
- A ratchet test lists the files that still name catalog tables; new code reads through the reader.
- No schema change and no configuration change.
