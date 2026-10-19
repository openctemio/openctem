### Behaviour change: findings of another remediation task are no longer dropped silently

- Accepting a suggestion, creating a task and adding findings to a task now
  answer 409 `FINDINGS_IN_OTHER_TASK` when some findings already belong to
  another active task, with `details.conflicts` per finding: the holding
  task, its title and owner when the caller can read it, and `can_move`.
  Before, an accept left such findings out without saying where they were.
- The request resolves conflicts with `"conflicts": {"skip": true}` or
  `{"move": [ids], "move_reason": "..."}`. A move needs write access to the
  holding task (403 otherwise), keeps the finding's SLA, writes a timeline
  entry on both tasks, tells both trackers and writes one
  `remediation_task.findings_moved` audit row per source task.
- Of two concurrent claims of one finding exactly one wins; the other
  answers 409 (RFC-098 §6.1).
