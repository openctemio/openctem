### Added: move findings between remediation tasks, split and merge tasks

- Move findings from one task to another, or out of any task (back to the suggestions pool, not proposed for
  that fix again). A different fix, a different owner, a task in verification or emptying the source needs the
  person's confirmation (preview shows the warnings); a closed task, another organization or findings outside
  the caller's access are refused. An emptied task is archived with a note; every finding and both tasks record
  the move; versions guard concurrent changes, and the reverse move undoes it.
- Split some findings into a new task of the same fix (another owner if named); merge tasks of the same fix.
- API: `POST /api/v1/remediation/moves`, `POST /api/v1/remediation/moves/preview`,
  `POST /api/v1/remediation/tasks/{task_id}/splits`, `POST /api/v1/remediation/tasks/{task_id}/merges`.
