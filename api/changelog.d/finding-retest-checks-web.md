### Added: retest checks on a finding in the console

- The finding drawer and the finding page have a "Retest check" section: attach an HTTP assertion (request and matchers, no code) or a nuclei template (pasted, uploaded or picked from the template library) to a finding that has no automatic retest, validate it (errors per field, tier, the template that would run), save, remove, and approve an intrusive check as a second person with scope approval rights.
- The saved check shows its digest, tier, calibration, approval state and last verdict; "Retest now" is offered for a finding with a check, and retest history names the custom check and its digest.
- Adding, editing and removing a check need the new permission `findings:retest_checks:write`.
