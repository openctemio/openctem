### Added: EPSS trend on the vulnerabilities list and the vulnerability page
- The EPSS sync keeps a daily score per CVE for 30 days (`epss_score_history`, only CVEs that findings carry).
- Each row of `GET /vulnerability-exposures` carries `epss_trend` (oldest first), drawn as a small line under the EPSS score.
- `GET /vulnerability-exposures/{id}` carries `epss_trend` when the caller has a finding of the CVE in scope, shown as a chart on the page.
- The history is never read by CVE id alone: another organization's CVE, or one only on an asset outside the caller's scope, gets no trend.

### Changed: the MCP tool `list_active_cves` uses the vulnerabilities list read
- It returns the CVEs of open findings the key's owner can see, in the list's risk order, with the same scope rules as the page.

### Removed: `GET /api/v1/vulnerabilities/active` and `GET /api/v1/vulnerabilities/active/stats`
- Use `GET /api/v1/vulnerability-exposures` (the vulnerabilities list), which takes every findings filter.

### Changed: the CVE catalog filters and table are translated
- Every label, column, count and empty or error message on the catalog tab of /exposures/vulnerabilities now comes from the English and Vietnamese catalogs.
