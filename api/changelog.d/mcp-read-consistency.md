### Fixed: MCP finding_stats and list_active_cves agree, and every CVE on an open finding is listed

- `list_active_cves` now reads as the same caller as `finding_stats` and the web console: a connection allowed to read all organization data lists every CVE of the organization, not only the CVEs of the person's own groups' assets. Before, `finding_stats` could report open KEV findings while `list_active_cves(kev_only=true)` returned none.
- One definition of a known exploited finding (its `is_in_kev` flag, kept in step with the CISA KEV catalog) for `finding_stats.kev_open`, the vulnerabilities list and the dashboard metric. Each CVE row carries `open_kev_findings`; their sum equals `kev_open`. The vulnerability catalog's own KEV date no longer marks a CVE known exploited on the vulnerabilities list.
- `list_active_cves` rows say `catalog_status` ("in catalog" or "not in catalog"), and the tools say that a finding's status is per finding and per asset.
- `list_assets` lists the riskiest assets first and returns `risk_scored_at`.

### Changed: MCP tools explain a partial data scope in one line

- When a connection reads only the person's groups' assets, the asset and finding tools add `scope_notice`: "You can see N of M assets; the rest are not assigned to a group you belong to." The organization's total is shown only to a person whose role reads it in the web console.
