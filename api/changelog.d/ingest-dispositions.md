### Added: every reported item has a disposition on its receipt, with the policy and version that decided it

- Receipts record each reported item: `created`, `still_detected`, `reopened`, `closed` and now `suppressed` (with the suppression rule and the policy version) as finding actions, and the items that did not become findings as `out_of_scope` (scope exclusion, uploader's scope), `rejected` (no target asset) or `quarantined` (sensor quarantine), with a fixed reason code. `filtered` and `held` are reserved for ingest filters and the review gate.
- New read `GET /api/v1/findings/imports/{id}/items` (`findings:read`; items on assets outside the caller's scope are hidden, items without an asset are shown only to unrestricted callers); the receipt detail counts items per disposition; the actions list carries `policy`, `policy_id` and `policy_version`. No evidence is kept for an item.
- A suppressed new finding is counted as suppressed on its receipt, no longer also as created.

### Fixed: ingest no longer runs without its suppression rules, and the automations of new findings survive a restart

- Ingest applies the tenant's suppression rules from a snapshot versioned by every write to suppression rules and scope exclusions; when the snapshot cannot load, the ingest fails and is retried. A failed lookup used to turn suppression off for the batch silently.
- The automations a new finding starts run from a durable `side_effects` ingest job after the batch is committed, batched, instead of a goroutine a restart lost.
- Migration `003380_ingest_dispositions`.
