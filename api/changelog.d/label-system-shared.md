### Changed: shared status components use the one label system

- Computed states (sensor, CI pipeline, scope, proxy, scan window and others), run statuses and the asset lifecycle badge now read as an icon plus plain text. Their text is no longer coloured on a faint tint, which failed contrast for the green and amber states in the light theme. Run statuses are translated (English and Vietnamese), "Timeout" now reads "Timed out", and a running run is a static half circle instead of a spinner.
- Remediation task and campaign statuses are lozenges tinted by workflow category; "On hold" is the waiting tone with a clock, and a cancelled or archived item is quiet instead of coloured.
- Sensor tags, the service-cell chips and "Pending setup" use the same tones, and the 11 px sensor tag text is gone.
- Fixed: the repository workspace passed an object where a class name was expected, so the branch scan status and the finding triage status showed no colour at all. They now show a health icon and a lozenge, with translated labels.
