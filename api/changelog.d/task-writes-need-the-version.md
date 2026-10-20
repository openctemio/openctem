### Behaviour change: every task write names the task version and is checked inside the transaction

- Splitting a task, requesting an exception on it, re-running its query and pausing or resuming auto include now require the `version` the caller read (`400` when missing, `409` when stale). Split used to accept no version and skip the check; the others never took one, so a concurrent edit silently won.
- Mark fixed and the exception request read the task's open findings under a lock on the task row together with the version check, so the findings they act on are the ones at the version the caller saw. Query re-run and pause/resume check it under the same lock.
- **Upgrade note:** `POST /api/v1/remediation/tasks/{id}/query/run` now needs a JSON body `{"version": <int>}`; `.../query/auto` and `.../exception` take `version` in their existing bodies; `.../splits` already documented it. The web console sends it.
