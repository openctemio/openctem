### Added: CI gate settings and baseline in the console, per repository

- A CI pipeline's drawer has a Settings tab: every gate field of its repository with the effective value,
  where it comes from (default, organization, business unit or this repository), the inherited value of an
  override, and the locks set above. Users with the CI gate policy permission override a field or reset it to
  the inherited value; a locked field offers only stricter values, and a change that loosens the gate asks
  for a reason (10 to 500 characters) and an optional end date (within 365 days). Readers see it read only.
- The same tab shows the gate baseline (when, how, by whom, branch, findings, when it blocks again) with
  "Record baseline now" and "Remove baseline", and links to the audit log for the repository's history.
- The pipelines list has a "Has overrides" filter (`?overrides=1`).
- The organization and business unit gate policy dialog locks fields, edits the baseline settings and shows
  how many repositories override each field, with a link to them. Saving keeps the baseline grace days,
  reason and end date, which every write replaces.
- A CI run's drawer splits findings into baseline (not blocking) and new, announces a baseline recorded on the
  first run with its due date, offers "Connect GitLab" (or "Install the GitHub App") when the check could not
  be posted for lack of a connection, and runs of the same commit are labelled "Attempt N of M".
