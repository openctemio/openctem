### Security: the task list's finding filter and the task write check respect the caller's data scope

- `GET /api/v1/remediation/tasks?finding_id=` no longer tells a caller with a restricted data scope which of their visible tasks hold a finding on an asset outside their scope: for such a finding the list is empty.
- A task with an active related member outside the caller's data scope is now read-only for that caller (changes answer 403 like a task with hidden primary members). Before, only hidden primary members blocked a change. The displayed `hidden_members` number still counts primary members only.
