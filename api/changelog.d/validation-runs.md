### Added: every finding validation is a run

- Validating a finding (re-verify, auto-validation, a ticket rescan) now
  records a run of kind `validation`. Its task and logs are on the Runs page,
  and it names the person who asked. The run ends with the verdict, or fails
  when the sensor fails the check, reports no verdict, or the check cannot be
  queued.
- Like a retest run, a validation run is about a finding. Reading it needs
  `findings:read` and the finding in the caller's data scope (404 otherwise),
  and the Runs list leaves it out for callers who cannot see it.
