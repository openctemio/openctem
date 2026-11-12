### Fixed: a failed load shows an error with Retry instead of an empty page or zeros

- Scans (counts), Workflows, Exceptions, Compliance (frameworks and totals), Business impact (figures, asset criticality, crown jewels), Validation (coverage), ATT&CK coverage, Executive summary (headline figures, process health) and Threat intelligence (overview, sync, CVE lookup) now show the shared error state with Retry and Report this problem when a read fails. Before, a failed read showed "No frameworks yet", zeros, an empty heatmap, or "CVE not found".
- A failed CVE lookup is told apart from a CVE that has no data: only a 404 says "not found".
- A new test fails when a route page that fetches data has no error state; the pages still to fix are listed in a file that can only shrink.
