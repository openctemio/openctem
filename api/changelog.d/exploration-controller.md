### Added: exploration leads are scored and dispatched

- A new background job (`ExplorationController`, module Scans, every 2 minutes, one replica) runs the
  exploration rules, then scores open leads in code (expected value: likelihood updated by the
  organization's own outcomes x the subject's value / the tool's learned duration, 20 % of each pass
  reserved for kinds of step never tried, a kind with 10 useless outcomes in a row demoted) and starts
  the best ones.
- Steps start only through the coverage run path: the dispatch gate (scope entries, exclusions,
  guardrails, zones), the signed job and the sensor's local policy apply, the target is always the
  subject asset's own name, and every step counts against the organization's coverage daily budget
  (`ASSET_COVERAGE_DAILY_BUDGET`). A refused target blocks the lead with the gate's code; nothing runs.
  At most 4 running leads per organization and one per asset and capability. Intrusive steps are never
  started by the system. Active steps run only while automatic coverage is on or a person approved them.
- Finished steps settle the lead with an append-only verdict and `yields` links, including "nothing
  found"; failed steps are retried until the lead type's attempt limit, then the lead is exhausted.
  Every state change is audited (`exploration.lead_state_changed`, `exploration.lead_verdict`).
