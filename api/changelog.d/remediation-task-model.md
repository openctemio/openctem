### Added: remediation tasks

- A remediation task groups the findings one fix closes, with one owner (a user and/or a group) and one
  deadline. Its state (open, in progress, verifying, done, closed without a verified fix, on hold, canceled,
  archived) is derived from its findings; it is done only when every finding is closed and at least one was
  verified fixed. The deadline is the earliest open finding's SLA deadline, tightened (never extended) by a
  manual deadline or the campaign's due date.
- A finding is the primary member of at most one active task and may be a related member of others; every
  change is on the task's timeline and the finding's activity.
- API: `/api/v1/remediation/tasks` (list, create, get, change, members, timeline) in the remediation module.
  A restricted member sees and changes tasks through their data scope only. Design: RFC-098.
- Migrations `002290_remediation_tasks` (four new tables), `002291_remediation_task_activity_type` and
  `002292_remediation_task_activity_type_validate` (the finding activity CHECK re-added `NOT VALID`, then
  validated without blocking writes).
