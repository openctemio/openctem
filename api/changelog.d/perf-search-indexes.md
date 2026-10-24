### Changed: search boxes use their indexes on large tenants

- The findings search (`q`) runs as one bitmap scan over its trigram, CVE and asset-name indexes. Its asset-name arm was a subquery the planner could not combine with the others, so every search read all of the organization's findings: 0.75-1 s at 500,000 findings, now 7-40 ms.
- The asset list search gets a trigram index on `assets.description` (migration 003400), so its name, description and alias match no longer reads every asset of the organization (75 ms to 0.3 ms at 100,000 assets).
- The audit log search gets a text-search index on the expression it matches (migration 003401): 0.8-2.5 s to under 1 ms at 300,000 audit rows.
- **Upgrade note:** both indexes are built `CONCURRENTLY` (no write lock). The audit index takes about 5 s per 300,000 audit rows to build and about 60 bytes per row.
