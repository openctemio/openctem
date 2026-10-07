### Behaviour change: informational findings get no SLA and no priority or risk weight

- Informational findings (severity `info`, or `none` = CVSS 0.0) get no SLA
  deadline by default. An SLA policy's `info_days` of `0` now means "no SLA for
  informational findings" and is the default for new policies; a positive
  value opts back in. The priority class no longer hands an informational
  finding a deadline. Migration 001180 moves policies still on a shipped
  default info window (90 or 365 days) to `0` and clears the deadline of open
  informational findings whose effective policy has no info SLA, so they stop
  counting as SLA breaches.
- Informational findings are classified P3 and skip the ownership floor,
  unless the CVE is in CISA KEV. A tenant priority rule can still raise them.
- The count-based asset risk score no longer adds points for informational
  findings (eight technology detections used to cap the finding component).
- **Upgrade note:** a tenant that wants a deadline for informational findings
  sets the info window of its SLA policy again after upgrading.

### Fixed: info is reported everywhere severity is counted

- `GET /findings/stats` reported informational findings under the key `none`,
  so the console, scheduled reports and the MCP stats tool showed 0 Info.
  It now reports `info` (info + none).
- Dashboard, trend, MTTR, component and pentest counts fold `none` into `info`;
  the dashboard severity maps always carry all five keys. Vulnerable
  components report `info_count`; MTTR analytics report an `info` average.
- Jira tickets for informational findings default to priority `Lowest`
  instead of the `Medium` fallback.
- A priority rule on severity `info` also matches `none` findings.

### Fixed: an asset can be saved as Not rated

- `assets.criticality` accepted `none` everywhere except the database CHECK,
  so saving an asset as Not rated failed. Migration 001180 adds it. The
  findings `asset_criticality` filter accepts `none`. New assets still default
  to `medium`: Not rated adds no criticality weight to risk, so it stays an
  explicit choice.
- The web console reads both scales from one source (`@/lib/severity`,
  `@/lib/criticality`): Info and Not rated appear in every filter, facet,
  summary, chart and mapping, and a guard test fails on a new hand-written
  list. The findings list has a saved "Hide informational" toggle.
