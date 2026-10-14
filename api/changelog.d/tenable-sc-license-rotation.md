### Added: license-aware rotation for Tenable.sc coverage

- A connector's rolling coverage can rotate more assets than the Tenable.sc license holds (`coverage_rotation`: `off` by default, `aging` or `recycle`), behind an administrator's acknowledgement that the customer's license terms allow it (`coverage_rotation_acknowledged`). `aging` waits for Tenable.sc's nightly cleanup of the rotation repository; `recycle` has the connector delete and recreate its rotation repository before the next batch, only after the previous batch was ingested.
- Every batch carries the connector's license guard, so a batch Tenable.sc has no room for is refused before anything is created and retried later; batches are sized from the license numbers reported after each import.
- Coverage batches settle the asset coverage ledger per target (assessed, no reply, unfinished, failed) instead of marking every dispatched asset covered, and the connector's state shows the coverage cycle with progress and an ETA.
- A recycle rotation stalls when a batch fails after it launched; `POST /api/v1/integrations/{id}/coverage/reactivate` (`integrations:manage`, audited) resumes it.

### Changed: rotation off rescans what the license already counts

- With rotation off, assets the connector assessed before are rescanned without using license headroom, and new assets are added only while the license has room.
