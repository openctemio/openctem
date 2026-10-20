### Changed: repository branch counters are recounted only when a finding's branch, severity or status changes

- The database trigger that maintains `repository_branches.findings_*` ran five counts and an update for every finding write that named severity or status, which includes every re-seen finding on a rescan. It now fires only when one of `branch_id`, `severity` or `status` really changed. The counts themselves are unchanged.
