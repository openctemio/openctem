### Added: finding practice (the program that triages a finding)

- Every finding now has a `practice`: `aspm`, `infra`, `external`, `cloud`, `compliance`, `offensive`, `identity`,
  `runtime` or `other`, derived when it is written from its type, source, tool and its asset's type and exposure
  (RFC-152). `compliance` means exactly a benchmark check result (`finding_type = compliance`).
- The findings list, stats, groups, export, saved views, the query language and the MCP `list_findings` tool filter
  on `practice` (`practice_not=compliance` lists vulnerabilities only) and on `compliance_result` (pass, fail,
  manual, not_applicable, error, unknown). The finding response and the export carry `practice`.
- Migrations `20261107130420_finding_practice` (two columns with a default and a CHECK added NOT VALID then
  validated: no rewrite, no write lock) and `20261107130421_finding_practice_index` (built concurrently).
- **Upgrade note:** existing findings read as `other` until the practice backfill runs (an explicit operator
  command, shipped separately); new findings and new sightings of open findings get their practice at once.
