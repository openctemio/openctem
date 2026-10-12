### Added: the run map updates live

- A run that changes (a step started, finished or was queued, the run
  settled or was canceled) tells the run page over the websocket channel
  `run:{id}`, at most once a second; the page refreshes the map, the run and
  its tasks at once instead of on its next poll. Subscribing needs
  `scans:read` and a run the viewer may read (a retest also needs its
  finding in the viewer's scope); the notice carries no data.
