### Changed: the vulnerability bundle import downloads only the delta when it can

- A platform that applied the previous bundle now downloads and verifies only
  the delta (its manifest and files); the snapshot is downloaded only on the
  first import or when the delta does not start at the applied sequence (a
  platform that fell behind, however far, takes the newest snapshot).
  Before, every run downloaded the full snapshot even when only the delta
  was applied.
- A delta that fails verification is refused and recorded in the
  `vulnfeed` status row; the importer does not fall back to the snapshot.
  Signature, key-set, sequence, expiry and hash checks are unchanged.
- The import runs every 20 minutes (was hourly), matching the hourly
  bundles; a run with nothing newer fetches only the key set and pointer.
