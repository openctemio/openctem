### Fixed: workflow runs no longer hang when a step's wake-up is missed

- A chained step waits until its predecessors' reports are ingested. If such
  a report failed or expired, nothing woke the step, and the run stayed
  "running" until its timeout. A failed report now wakes the step at once.
- If the platform stopped between saving a step's plan and creating its
  tasks, the step never started. The new `stalled-run-repair` controller runs
  every minute and handles both cases:
  - it re-plans such a step after 2 minutes;
  - it advances any running workflow run that has a step left to start but
    nothing queued, running or being ingested for 2 minutes.
