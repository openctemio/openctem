### Behaviour change: a remediation campaign is a program of tasks

- A campaign holds remediation tasks (a task is in at most one campaign), never findings. Its progress is derived from
  its tasks on every read: `summary` (tasks, live, done, overdue, tasks outside your scope, findings of the tasks, closed
  and verified) replaces the stored counts. New `POST /api/v1/remediation/campaigns/{id}/tasks` (`task_ids`, `move`) and
  `DELETE /api/v1/remediation/campaigns/{id}/tasks/{task_id}`; create takes `task_ids`; a task in another campaign
  answers 409 `TASKS_IN_OTHER_CAMPAIGN` unless `move` is set. `GET /api/v1/remediation/tasks?no_campaign=true` lists
  tasks in no campaign.
- Lifecycle: draft, active, completed, canceled. Completing needs every task closed and one done; the progress controller
  completes an active campaign whose tasks are done and reopens a completed one when a task is live again. `paused` and
  `validating` campaigns become active (migration `003115`, audited).
- Data scope: a restricted member sees a campaign they created or own, or one with a task holding a finding in their
  scope (other tasks are a count), and changes it only when every task of it is in their scope; a task moves between
  campaigns only when they may change both. The campaign's due date bounds its tasks' deadlines while it is draft or
  active.
- The campaign's Jira epic moving to Done marks the campaign's live tasks fixed (a fix claim per finding). The ticket
  field and status mapping preview of a "task" now renders a real remediation task (its state values replace the old
  campaign statuses in `task.status`; `task.tags` is gone).

### Removed: campaign finding filters and the endpoints built on them

- `GET /api/v1/remediation/campaigns/{id}/findings`, `POST .../{id}/resolve`, `POST .../{id}/refresh`, the
  `finding_filter`, `finding_count`, `resolved_count`, `verified_count`, `progress` and `risk_*` fields, and the
  remediation key backfill's campaign retargeting (the `refingerprint -remediation-keys` report no longer lists
  campaigns). Migration `003115_remediation_campaigns_drop_finding_filter` converts the campaigns created since
  `003061` and drops the columns.
- **Upgrade note:** destructive migration (column drop): stop the API during the deploy, since the previous release
  reads the dropped columns. Its down brings the columns back empty.
