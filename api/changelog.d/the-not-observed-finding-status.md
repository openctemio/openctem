### Added: the `not_observed` finding status

- **`not_observed`: not seen lately, not fixed** (research 18, owner
  decision O2). Recent scans no longer report the finding, but nothing
  proves the check ran against it. It is an open status: never counted as
  fixed, no `resolved_at`, and its SLA keeps running. Only the platform sets
  it; a sighting reopens it (not counted as a regression), and it reaches
  `resolved` only through a retest or a `findings:verify` holder.
- **Feature-branch expiry writes `not_observed`** instead of `resolved`, so
  "not seen for N days on a branch" no longer counts as a fix in fix-rate
  or MTTR. Migration 000640 moves existing `resolved` / `branch_expired`
  rows to `not_observed` (no other row is touched) and adds a CHECK
  constraint on `findings.status`, which had none.
- Retest runs on `not_observed` findings. The web labels the status
  "Not Observed" and lists it in the "Open" filter group.
