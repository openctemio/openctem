### Fixed: remediation task pages (validator, paging, priority, permissions, edit scope)

- The validator picker chose a person, but a task's validator is a group: every
  save failed. It now lists groups and sends the group id.
- The task list read only the first 50 tasks: metrics, the board, search and
  "add to an existing task" were wrong beyond that. It now reads every page.
- Priority uses the API's values (critical, high, medium, low); the web no
  longer sends `urgent`.
- Write controls (new task, bulk move, row status actions, every edit in the
  task drawer) show only with `findings:remediation:write`.
- Editing a task keeps its other scope conditions and never adds linked
  findings to a task tracked by a fix.
- Priority, status and validator labels in English and Vietnamese.
