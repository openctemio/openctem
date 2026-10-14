### Fixed: the coverage ledger settles each asset from its own target

- A run's step can end with more tasks than chunks (claim-time splits,
  follow-ups of unfinished targets). The coverage loop settled every pair of
  a run from the run's overall status, so one failed task failed every pair
  and a run that completed covered targets nobody ran. It now settles each
  pair from its target's own outcome across every task of the run: done
  covers it, a failure keeps its class (unreachable, timeout, tool error,
  egress refused), a skip blocks it with the reason, a task that failed
  whole fails its targets with its error, the run's unfinished targets
  (a connector's included) fail as unfinished, and a target no task carried
  fails as not dispatched.
