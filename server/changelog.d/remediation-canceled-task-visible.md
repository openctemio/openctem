### Fixed: a canceled remediation task stays in the task list and opens by id

- Canceling a task releases its findings (they may join another task). The task's visibility check counted active members only, so a canceled task disappeared from `GET /api/v1/remediation/tasks` and `GET /api/v1/remediation/tasks/{id}` answered 404 for every caller with a data scope: a restricted member, and an administrator from whom a private bug-bounty program asset is hidden. A canceled task is now seen through the findings it held when it was canceled, so it stays listed with state `canceled`, `?state=canceled` finds it, and its page and timeline open.
- Who may see it does not change: a caller who could not see any of its findings before the cancel, and every other tenant, still get 404. The task's stored counters are unchanged (a canceled task holds no findings).
- Docs: server/docs/rfcs/RFC-098-remediation-tasks.md (the `canceled` state row)
