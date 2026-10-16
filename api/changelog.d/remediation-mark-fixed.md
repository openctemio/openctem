### Added: mark a remediation task fixed; regressions open a linked task

- "Mark fixed" on a task claims the fix of each of its open findings: each goes to fix applied through the same
  rules as the findings list (a note, `findings:fix_apply`, the asset owner's own findings), and a proof-of-fix
  re-check is queued per finding. Nothing closes: each finding closes on its own evidence, and the task is done
  once every finding is closed and at least one was verified fixed. Findings not updated are listed with the
  reason. API: `POST /api/v1/remediation/tasks/{task_id}/resolve`.
- A finding that reopens after its task is done no longer reopens the task: it moves to a new task
  ("Regression: …", same fix and owner) linked to the done one.
