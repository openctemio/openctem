### Added: vulnerability intelligence with sources and dates in the finding drawer

- Ingest keeps the scanner advisory's references (http(s) only, at most 25), published and modified dates and the primary CVSS source on the finding, since a report never writes the shared CVE catalog.
- `GET /api/v1/findings/{id}` returns `intel`: those facts plus the date of the EPSS score and the CISA KEV date added (and ransomware use) for the finding's CVE.
- The finding drawer has an Intelligence section: every CVSS score with its version, vector and source, a note when the sources disagree, the CWE, KEV status with its dates, EPSS with its percentile and date, published and updated dates, the identifiers (CVE, GHSA, OSV) linked to their authority, and the references with advisory databases and fix commits first.
