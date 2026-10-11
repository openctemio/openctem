### Fixed: destructive actions in the console ask before they act (part 1)

- Deleting a dashboard or a saved view, deleting an automation workflow, cancelling a scan run,
  disabling scans in bulk, resolving findings or exposures in bulk, unlinking a finding from a
  remediation campaign or task, cancelling an invitation, revoking an authorization letter, and
  suspending or ending a program now open a confirmation that names the object and the
  consequence. One click no longer changes data.
- Deleting an automation workflow from its row menu works again: the delete fired before the
  workflow id was set and was refused.
- The shared confirmation dialog: Cancel has the focus (Enter on open cancels), both buttons stay
  disabled while the action runs, Escape cannot close it mid-request, and its text (including
  "Type ... to confirm") is translated. Erasing a member's personal data and bulk deletes of ten
  or more scans ask the user to type the email or the count.
