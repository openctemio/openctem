### Added: console for remediation tasks from a query

- Tasks: "New task from query" opens a query box (field and value suggestions, live check), a preview
  (matches, severity, top assets and owners, sample, earliest SLA deadline, suggested owner, matches held
  by other tasks) and the snapshot / auto include choice with its guardrails and cap.
- Findings: "Task from filters" turns the current list filters into the query (filters that cannot be
  carried over are named).
- Task page: "Created from a query" shows the query, the mode, the auto include state (with the reason
  when suspended), pause and resume, and "Re-run query", which adds new matches only after confirmation.
