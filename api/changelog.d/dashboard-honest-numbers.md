### Fixed: dashboard numbers say what they count

- `findings.overdue` in `GET /dashboard/stats` is now computed (open findings
  past their SLA, equal to the executive summary's `sla_breached`); it was
  always 0.
- `findings.total` and `findings.by_severity` count open findings; they counted
  every status. `findings.by_status` still lists every status.
- `sla_compliance_pct` (executive summary) is the share of open findings that
  carry an SLA and are not past it, and is `null` when none does; it was 100
  for an organization with nothing to measure and counted findings without an
  SLA as compliant.
- `mttr_critical_hours` and `mttr_high_hours` (executive summary) and
  `overall_hours` (MTTR analytics) are `null` when nothing was remediated, not
  0. New: `mttr_{critical,high}_median_hours`, `..._p90_hours`, `..._sample`
  and `overall_median_hours`, `overall_p90_hours`. MTTR analytics leaves out a
  severity or priority bucket with no remediated finding. **Upgrade note:** API
  clients must accept `null` in these fields.
- New `kev.tenant_open_count` in `GET /threat-intel/stats`: the tenant's open
  findings in the KEV catalog. The CTEM loop shows it instead of the size of
  the catalog.
- Weekly velocity is computed with two range scans over the window instead of a
  join of every week with every finding, with the same result.
- Console labels match their formulas: open findings, open within SLA, time to
  fix (median with the 90th percentile), crown jewels with open findings,
  crown jewels on an attack path, and connector dispatch freshness for the
  scan-coverage row. A figure that is not measured shows a dash.
