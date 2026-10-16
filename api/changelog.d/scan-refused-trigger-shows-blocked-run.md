### Fixed: a refused Run now shows its blocked run at once

- When Run now is refused (no sensor online with the tool, targets out of
  scope), the API records a blocked run, but the scan page kept showing
  "No runs yet" until its next poll. The run history and the scan list now
  refresh after a refusal as well as after a start.
