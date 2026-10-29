### Changed: vulnerabilities list performance

- `GET /api/v1/vulnerability-exposures` answers an organization with 300,000 findings in under a second (was 3 to
  4 s): one hash aggregation per CVE without sorting the findings, JIT compilation off for the read, the per-CVE
  hash tables held in memory. A database test holds the list to a 1.5 s budget at 200,000 findings and fails on a
  JIT-compiled or spilling plan.

### Security: vulnerabilities list hardening

- The route refuses the deprecated findings param names (`severities`, `statuses`, `search`...) and the legacy
  `branch_status` with 400 instead of mapping them, and sends no deprecation headers.
- The product and version joins of the list and the vulnerability page also check the row is global or the
  caller's organization's.
