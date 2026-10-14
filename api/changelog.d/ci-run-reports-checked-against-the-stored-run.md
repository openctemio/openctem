### Security: a CI run's reports are checked against the stored run, not the request's snapshot

- An upload now reserves one of the run's report slots in a single
  statement, only while the run is still running. Before, the status and
  the report count came from the snapshot taken when the run token was
  checked, so concurrent uploads (or the files of one ZIP) could pass the
  200-report cap, and a report could be recorded after the verdict.
- A verdict is stored only if no report was recorded while it was being
  computed; otherwise the run is judged again with that report (up to three
  times, then `409`).
- A report or a VEX document that arrives after the verdict is refused with
  `409` instead of being recorded without the verdict seeing it.
