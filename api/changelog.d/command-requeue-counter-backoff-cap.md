### Fixed: a command that keeps returning to the queue is delayed and finally failed

- Every path that puts a command back to `pending` (unclaim while the job signer is down, voluntary release, refusal re-route, lease expiry, stall, withdrawn sensor, scan window deferral) now counts the return in `commands.requeue_count`. After the first return the next offer is delayed (5 s doubling to 5 min; a refusal re-route is counted but not delayed, other sensors may take it at once), and after 50 returns the sweep fails the command with the reason "max re-queues exceeded". Before, a command could cycle indefinitely (one live command was requeued 150 times in 2.5 hours) with `dispatch_attempts` unchanged, writing the row on every loop.
- Dispatch attempts keep their meaning (work a sensor took and lost); a hand-back or a window deferral still never counts as an attempt.
- Migration `003186` adds `commands.requeue_count` (constant default, no rewrite) and `command_requeue_backoff_secs()`.
