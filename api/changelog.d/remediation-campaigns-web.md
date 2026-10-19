### Changed: the campaign pages show programs of remediation tasks

- `/remediation/campaigns` lists each campaign with its owner and team, due
  date (late campaigns say "overdue"), status, tasks (with the overdue and
  out-of-scope counts) and the findings of its tasks closed so far, with
  server-side paging and status counts.
- A campaign's page shows its progress and its tasks, and lets a writer edit
  it, start, complete (only once no task is still open), reopen, cancel or
  delete it, add open tasks (moving a task from another campaign is
  explicit) and remove a task from it. A caller who may not change the
  campaign (some of its tasks are outside their data scope) sees it read-only,
  and tasks outside their scope only as a count.
- The task page links to the campaign the task belongs to.
- Status chips on the campaign and task pages come from one status registry,
  so a draft campaign reads "Draft" everywhere.

### Removed: finding-based campaign screens

- The campaign task drawer, the findings picker, "mark the campaign fixed",
  the completion confirmations and the finding-filter editing are removed
  with the API endpoints they used. The web client's unused
  `/api/v1/remediation/{id}` endpoint builders and hooks are removed.
