### Changed: the Approvals badge comes with the session bootstrap

- `GET /me/bootstrap` returns `badges.pending_approvals`: the finding approval
  requests waiting for a decision, counted as `GET /approvals` counts them
  (the caller's data scope applies). Only for callers with `findings:approve`
  and the findings module on, the same audience the badge had.
- The web reads it from the bootstrap instead of asking `GET /approvals` on
  every page load, and refreshes it after a decision on the inbox.
