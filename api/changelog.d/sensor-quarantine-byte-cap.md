### Security: the results quarantine caps the bytes an organization's pending items hold

- Quarantined sensor results stay pending until someone reviews them. The limits counted items only: 1000 per organization at up to 16 MiB each. So one organization could keep about 16 GiB of pending payload in the shared database.
- Pending items of one organization now hold at most 512 MiB together. A report beyond that is refused like any report over a quarantine limit: v1 answers `RESULTS_QUARANTINE_FULL`, and v2 reports the item error `quarantine_full`.
