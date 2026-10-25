### Fixed: a severity filter for Informational also matches findings stored as none

- Findings stored with severity `none` (CVSS 0.0, and scanner templates that only detect a technology, a WAF or an API description) were counted as Informational but left out when filtering by `severity=info`. The filter now matches both values on the findings list, stats, groups, export, quick views, bulk actions by filter, saved views, the query language, MCP tools and the vulnerability catalog.

### Behaviour change: the findings work views leave informational findings out by default

- The quick views Active, My queue and SLA breached now add `informational=false` unless the member's preference (`findings_informational` in `PUT /api/v1/users/me/preferences`) or the organization's default (`PATCH /api/v1/organization/settings/finding-views`, owner or administrator, audited) includes them. Needs triage always leaves them out. All findings, Closed and API calls without the filter are unchanged.
- New list filter `informational=true|false`. `GET /findings/quick-views` returns the resolved choice as `include_informational`.
