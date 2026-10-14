### Changed: a task waiting on a few busy hosts starts its other targets

- When a sensor has free scan slots, a queued task of a run step waits whole no longer because a few of its hosts are busy in another task: the claim splits it. The targets on free hosts start at once in the task; the others wait in a new task of the same step and run, which starts when their hosts are free.
- Only tasks with at most half of their targets on busy hosts are split, and a task is split at most 3 times, so a step never breaks into a task per host. Concurrent claims split a task once. The step, its targets' outcomes and its progress count both parts.
- New metric `command_host_splits_total`. Migration: `commands.host_splits` (smallint, default 0; no table rewrite).
