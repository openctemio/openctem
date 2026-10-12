### Fixed: runs say when an automation or a retry started them

- A scan run started by an automation's `trigger_scan` step now has
  `trigger_type` `automation` (it said `manual`). Its run context names the
  automation, the automation run and the step (`automation_cause.node_key`).
- A run started by the retry of a failed run has `trigger_type` `system`
  (it said `manual`).
- Migration 001309 allows `automation` and relabels earlier automation runs
  (`triggered_by` `workflow:<id>`).
