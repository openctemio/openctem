### Added: MCP list tools page and list_findings takes the findings list's filters

- `list_findings` reads the findings list (GET /findings) with its own parser and order: `state`, `asset_id`, `cve`, `kev`, `min_epss`, `priority_class`, `sla_status`, `assignee` (`me` or a user id), created and updated ranges and `sort`, beside severity, status, source and search. It returns priority class, KEV, EPSS, SLA status and first detection per finding.
- `list_findings`, `list_active_cves`, `list_assets` and `list_remediation_groups` take `page` and `limit` and return `total`, `has_more` and `next_page`.
- `get_exposure_chains` says that a length 0 chain is a directly exposed asset, counts multi-hop chains, and says plainly when no asset relationships exist to build longer paths.

### Fixed: one fix source for the vulnerabilities list, the package inventory and the remediation groups

- `has_fix` is true when the scanner listed fixed versions or said a fix is available, or a finding is in a remediation group; each vulnerabilities list row lists its remediation group titles (`remediations`). The `remedy_available` column, which defaults to true, no longer marks every package finding as fixable in the package inventory.
- The pentest TLP limit for AI applications now also applies to `list_active_cves` and `finding_stats`.
