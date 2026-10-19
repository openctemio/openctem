### Added: a detail panel to judge each remediation suggestion

- The Suggestions inbox opens a side panel per suggestion (`?suggestion=<id>`,
  Enter or the title; j/k move, Esc closes): what accepting creates (one
  task per owner, owner changeable, deadline from the earliest SLA), the fix
  (package current to target with the install command and a major-version
  warning, the specific solution text, rotation steps, the scanner's code
  change as plain text), every finding with file:line or its location, rule,
  status and SLA, the assets with criticality and owner, and why the findings
  were grouped with the confidence in words (the fix key only under technical
  details).
- Cards count with correct plurals, explain risk points and name the
  confidence; snooze asks for a date (undo in the toast); owner pickers are
  searchable and say why a list is empty (no permission, none yet with a link
  to create a team, loading, failed).
- When another task took some findings since the suggestion was made, the
  accept asks per finding: skip (default) or move with a reason when the
  person may change that task.
