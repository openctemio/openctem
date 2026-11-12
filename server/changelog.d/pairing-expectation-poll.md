### Fixed: the Add sensor dialog sees the sensor that used its pairing code

- After "Create pairing code first", the dialog checked the code once and then
  stopped: its 1-second countdown restarted the 3-second check before it ran,
  so it stayed on "Waiting for the sensor" and the fingerprint never appeared
  for approval. It now checks every 3 seconds until the fingerprint is known
  or the code ends, and stops when the dialog closes.
- The waiting step has a "Check now" button, and a failed check says so there
  (it is not retried on its own, so a rate limit is respected).
- The same restart affected the proxy pool test results, finding retest
  status, a scan's latest runs and the platform console's feed list on pages
  that re-render often; a test now refuses an inline polling interval.
