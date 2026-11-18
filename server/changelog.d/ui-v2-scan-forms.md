### Changed: Clone scan, Quick scan and Scan assets use the shared form dialog (redesign branch)

- Clone scan, Quick scan and Scan assets are `FormDialog`s: label above each field, help and errors tied to the
  field, Cancel and one primary action, Enter submits, and the reason a disabled primary action is off is read with
  it. Fields, defaults, checks and requests are unchanged.
- Clone scan lists what is copied as label and value rows. Quick scan is 672 px wide; once a scan has started, its
  one action is Done, and Enter in the "Save as scan" name saves it.
- The line editor of a pasted target that is not valid is no longer a form inside the dialog's form: saving the line
  no longer starts the scan.
- New scan and Edit scan: a missing name, scanner or workflow is marked at its field once the What step shows its
  problems, so "Go to What" puts focus on the field to fix. The scanner, workflow and Tenable.sc connector pickers are
  as wide as their field.
- Docs: none (the console dialogs keep their fields, checks and requests; user guides describe them by field)
