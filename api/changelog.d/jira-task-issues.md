### Added: one Jira issue per remediation task

- A person who may change a remediation task creates its Jira issue
  (`POST /api/v1/remediation/tasks/{task_id}/ticket-links`, `remediation:write`)
  in a project configured for ticketing; a task has at most one issue. The
  issue carries the task's title, fix, finding count, deadline and a link back,
  and names no finding.
- The issue follows the task: in progress and done move it, and every move of
  the task posts a progress comment (findings closed, verified, fix claimed,
  in progress, open). A missed push is retried every minute.
- Moving the task's issue to Done in Jira claims the fix of the task's open
  findings; OpenCTEM verifies each of them. Our own moves are not read back.
