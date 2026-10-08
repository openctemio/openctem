### Added: a run's live map

- `GET /scan-runs/{id}/map` (`scans:read`) returns the run drawn on the
  workflow version it executes: each step's state (pending, waiting for a
  sensor, running, succeeded, partial, failed, skipped, canceled) with its
  reason and error class, chunks by state, findings, planned inputs and
  outputs by asset type, and each dependency with what the upstream step
  produced. Output counts cover only the assets the caller may see; a run
  of another organization, or a retest of a finding outside the caller's
  scope, is not found.
