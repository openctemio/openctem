### Changed: "Add to remediation" on the findings list creates or joins a remediation task

- The row action and the bulk "Remediation task" action on the findings list
  open one dialog with two modes: a new task (title, owner, team, deadline,
  optionally a draft or active campaign) or an existing open task. They no
  longer write a campaign's finding filter.
- When some findings are already in another open task, the dialog lists them
  (a task the caller cannot read shows as "a task you cannot see") and offers
  to skip them or, where the caller may change the holding task, to move the
  selected ones with a reason. The server decides; the dialog only sends
  `conflicts: {skip}` or `conflicts: {move, move_reason}`.
