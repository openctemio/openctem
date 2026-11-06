### Added: asset liveness, and findings of gone assets close as obsolete

- Every asset now has a liveness state read from the coverage loop's per-target verdicts: alive, unreachable (checks
  got no answer, 3 times over 72 hours by default), unresolvable (the name has no address or the lookup failed) or
  gone (no address 3 times over 72 hours from two scan zones or sensors, or over 7 days from one; the dangling DNS
  check ran clean; not pinned by a person). An edge protection that blocks a check counts as an answer. A dangling
  name is never gone: it stays unresolvable with reason `dangling` and its takeover risk stays a finding.
- Organizations can turn on `liveness.close_findings_when_gone` in the asset lifecycle settings: open findings of a
  gone asset (version-match findings included) then close as resolved / `obsolete_asset` (never counted as fixed)
  and reopen to their previous status, with the SLA deadline kept and not as a regression, when the asset resolves
  or answers again. Every move is on the finding's timeline and audited; owners and administrators are told. At
  most 50 assets with open findings become gone per day by default.
- Asset responses carry `liveness` (state, since, last check and which zone or sensor made it). The asset lifecycle
  dry run reports assets per liveness state and the findings a pass would close and reopen.
- Thresholds are tenant settings with safe floors; turning closing on or lowering them is a loosening (step-up,
  high-severity audit, owners told).
- Migration `asset_liveness` adds the evidence table and seeds it from the coverage ledger.
- **Upgrade note:** closing is off by default. Run the asset lifecycle dry run and review `liveness` before turning
  it on.
