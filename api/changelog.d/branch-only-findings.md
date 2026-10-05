### Behaviour change: findings seen only on a feature branch are not counted as exposure

- A finding first seen on a branch that does not count (not the default, a
  protected, a `main` or a `release` branch) is marked `branch_only`
  (migration 001132). The findings list, stats, groups and export leave it out
  unless the request filters on `branch_only`, a branch, a scan or ids
  (`branch_only=true` lists them); SLA escalation skips it; new-finding
  workflows (notifications, ticket rules) and regression follow-ups do not run
  for it. The CI gate, the run and the branch pages are unchanged.
- When a counting branch sees it, or its branch starts to count, the mark is
  cleared and its exposure starts then: `first_detected_at` moves to that
  time and the SLA deadline keeps its length from there. Its workflows run
  then.
- A branch-only finding no branch still shows (deleted, or merged and no
  longer scanned) becomes `not_observed` (`branch_expired`) through the finding
  lifecycle job, with an activity entry.
- A repository with no known default branch hides nothing. Findings response:
  new `branch_only` flag. See `docs/architecture/branch-only-findings.md`.
