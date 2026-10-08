### Behaviour change: every finding status change follows the lifecycle

- The finding lifecycle is now enforced on every write path. Moves a person may make are `ValidStatusTransitions`; the moves only the platform makes on evidence (a covered scan, a retest, a source mitigation, a VEX statement, an approved suppression rule, a stale source or expired branch, a regression reopen) are listed once in `PlatformStatusTransitions`.
- Automated SQL writes (coverage and default-branch auto-resolve, source-mitigated resolve, VEX not_affected, stale-source and branch expiry, regression reopen, suppression lift and re-link) take their from-states from the domain lifecycle; a list that drifts stops the server at start.
- Bulk status changes (bulk update, verify or reject by filter, approval) change only findings whose current status may move to the target; a finding that changed since the request is left alone.
- A retest whose decision is not a lifecycle move is refused and rolled back.
- Requesting or approving a false positive or accepted disposition is refused (400) when the finding's current status cannot move there. An expired risk acceptance reopens the finding only while it is still accepted.
- Triage (confirm) is refused for a finding that cannot move to confirmed (for example fix_applied).
- `open` was never a finding status; SQL filters no longer list it.
