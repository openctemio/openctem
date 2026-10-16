### Added: metric for the findings a suppression rule decides

- `openctem_suppression_rule_hits_total{applied_by}` counts the findings an approved suppression rule decided: `ingest` for new findings a rule matched as they arrived, `approval` for open findings it closed when approved. A finding is counted once per rule. The labels carry no tenant, rule or finding id; the per-rule breakdown stays in `finding_suppressions`. Documented in `docs/operations/monitoring.md`.
