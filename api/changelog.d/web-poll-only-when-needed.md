### Changed: the web console polls only while it can change something

- The permission sync no longer polls every 2 minutes while the real-time
  connection is up; role changes still apply on the next request.
- Scan pages refresh their run lists every 10-30 seconds only while a run is in
  progress, and every 2 minutes otherwise.
