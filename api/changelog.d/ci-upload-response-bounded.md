### Fixed: a large CI upload is no longer taken for a failed upload

- The response to a CI report upload listed every result of the report that already carries a decision
  (`known`), so it grew with the report. Past about 95,000 decided results it was larger than what the CI
  runner reads (8 MB), and a report the platform had stored counted as a failed upload: the gate then failed
  with "not uploaded". `known` now lists at most 10,000 results (lowest indexes first, about 1 MB); the new
  `known_total` counts them all and `known_truncated` is true when some were left out. Older runners keep
  working: they read `known` as before and show the results left out of it. The gate on the platform judges
  every finding either way.
