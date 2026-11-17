### Changed: the approval requests page follows the list pattern, with a shared queue add-on (redesign branch)

- Approval requests (`/findings/approvals`): a title row names the view ("Pending requests", "All requests") and
  shows its count once, with Refresh; the Status lens is the toolbar's filter token; the table freezes the finding
  at the start and the decision at the end, keeps every row on one line and gains the Display menu (density,
  columns). The page header no longer repeats the pending count.
- Decide by is a date and reads "Overdue" with the date once it has passed. Acceptance end is a date.
- Your own request shows "Your request" in place of Approve and Reject, with the reason on hover and focus, and
  written out on a phone.
- Empty states: no request yet, nothing waiting (with "Show all requests"), and no request with the chosen status.
  A refused read says there is no access; a failed read keeps the tabs and the toolbar and offers Retry.
- Phone cards show the finding, status, requested status, approval tier and progress, requester, decide by,
  acceptance end, the justification (with its AI mark) and the decision controls.
- Group exceptions use the same table pattern (name first, one-line rows, decide-by date, loading and error in
  the table).
- Every outcome (approved, rejected, refused, reminded, canceled) is also written to a status region for screen
  readers. Approve and Reject are named after the finding for assistive technology.
- The reject dialog shows the AI mark of a request an AI proposed.
- No behaviour, permission, confirmation or limit changed: Approve and Reject need `findings:approve`, Remind and
  Cancel need `findings:write` and the request being yours, a reminder is refused within an hour of the last one,
  the sole member's own approval is offered only when the API allows it.
- Docs: none (internal redesign branch)
