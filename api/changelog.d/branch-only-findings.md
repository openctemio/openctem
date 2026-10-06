### Behaviour change: findings seen only on a feature branch are not counted as exposure

- A finding first seen on a branch that does not count (not the default, a
  protected, a `main` or a `release` branch) is marked `branch_only`
  (migration 001138). The findings list, stats, groups and export leave it out
  unless the request filters on `branch_only`, a branch, a scan or ids
  (`branch_only=true` lists them); SLA escalation skips it; new-finding
  workflows (notifications, ticket rules) and regression follow-ups do not run
  for it. The CI gate, the run and the branch pages are unchanged.
- When a counting branch sees it, or its branch starts to count, the mark is
  cleared and its SLA clock starts then (the deadline keeps its length,
  measured from that time). Its workflows run then. `first_detected_at` keeps
  the first sighting, so the CI gate's notion of "new" is unchanged.
- The CI gate's findings link adds `branch_only=true` for a run on a branch
  that does not count.
- A branch-only finding no branch still shows (deleted, or merged and no
  longer scanned) becomes `not_observed` (`branch_expired`) through the finding
  lifecycle job, with an activity entry.
- A repository with no known default branch hides nothing. Findings response:
  new `branch_only` flag. See `docs/architecture/branch-only-findings.md`.
