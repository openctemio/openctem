### Changed: scan run lists update from real-time notices

- The scan page and the runs tab refresh when a live run changes, from its
  `run:{id}` notices, instead of polling every 10-30 seconds; they poll only
  while the real-time connection is down, and every 2 minutes to notice new
  runs.
