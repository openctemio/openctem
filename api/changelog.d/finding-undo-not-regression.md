### Fixed: undoing a resolve is not a regression

- A person moving a finding back from resolved (the drawer's Undo, a
  correction, a bulk status change) no longer sets `is_regression` or counts
  in `reopen_count`, so the reopen rate counts only fixes that evidence shows
  did not hold (a scan sees the finding again, a retest fails, a fixed VEX
  statement is withdrawn). Migration `002205` updates the regression trigger.
- The drawer no longer offers Undo after a resolve; reopening is a deliberate
  move from the status control.
