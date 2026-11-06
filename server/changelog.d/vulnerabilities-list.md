### Added: vulnerabilities list

- `/vulnerabilities` (main navigation, under Findings) lists one row per CVE across the assets you can see, sorted by
  risk (worst priority, known exploited, emerging threat, EPSS, CVSS, reach): title and aliases, KEV with its due
  date, public exploit, emerging-threat alert, severity and CVSS, EPSS, affected assets (internet-facing), affected
  product and versions, fixed version, SLA breaches and how much is already in a remediation task. Every count opens
  the findings list with the same filters; a row opens the vulnerability page.
- Filters: known exploited, public exploit, emerging threat, past SLA, EPSS threshold, fix known or not, severity,
  priority, source, asset group, the findings lens (open, fixed, accepted or false positive, all) and a search on
  the CVE, advisory alias or title. Every filter is in the URL.
- API: `GET /api/v1/vulnerability-exposures` takes every `GET /findings` filter param plus `kev`, `exploit`,
  `has_fix`, `emerging`, `past_sla`, `epss_gte`, `q` and `sort`, and needs `vulnerabilities:read` and
  `findings:read`. A row's counts equal the findings list filtered by that CVE for the same person.
- The vulnerability page's affected assets show where on each asset the findings point (port, URL path or file).

### Removed: Active CVEs tab

- The "Affecting my assets" list on Exposures, Vulnerabilities is replaced by `/vulnerabilities` (linked from that
  page's header). The page keeps its summary and the CVE catalog. `GET /api/v1/vulnerabilities/active` stays for now.
