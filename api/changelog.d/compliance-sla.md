### Behaviour change: compliance findings have their own SLA and leave vulnerability figures

- SLA policies take a `practice`: empty (every finding except compliance, as before) or `compliance` (only
  benchmark check results). A compliance finding is governed only by compliance policies (asset, then the tenant
  default, then the platform compliance windows P1 30, P2 90, P3 180 days); the known exploited cap does not apply.
  A vulnerability is never governed by a compliance policy (RFC-152).
- Dashboard figures (executive summary, KPIs, SLA percentage, trends and the dashboard facts) leave compliance
  findings out; a practice change refreshes the asset's facts.
- Deadlines stay tighten-only: a compliance finding that already has a shorter deadline keeps it until an explicit
  re-baseline.
- Migrations `20261107133346_sla_policy_practice` (nullable column, CHECK, the default index rebuilt per practice on
  the small policy table) and `20261107134605_dashboard_facts_without_compliance` (function replacement).
- **Upgrade note:** no figure moves at deploy: existing findings read as practice `other` until the `finding-practice`
  command is applied.
