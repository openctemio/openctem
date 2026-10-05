# Branch-only findings

A CI run or a repository scan on a feature or merge-request branch writes its
findings into `findings`, like any other scan. A finding that exists only on
such a branch is not exposure yet: the code has not reached the default or a
release branch. Counting it would inflate dashboards, start SLA clocks and
send notifications for code that may never merge. Such a finding is
**branch-only**: it stays visible where branch work is reviewed (the CI gate,
the run, the branch pages, a filtered findings list) and is left out of the
exposure views.

Migration `001131_finding_branch_only`. RFC-051 §5 (CI uploads).

## Which branches count

`branch_counts_as_exposure(branch_id)` (SQL, the one rule) is true when the
branch is

- the repository's default branch (`is_default`), or
- protected (`is_protected`), or
- of type `main` or `release` (the branch type rules: per asset, per tenant,
  then the defaults `main`/`master` and `release/*`), or
- in a repository with **no known default branch yet**: nothing is hidden
  until the platform knows which branch is the baseline.

A branch that no longer exists counts (fail open: a finding is never hidden by
a missing row). Feature, hotfix, develop and other branches do not count.

## The mark

`findings.branch_only` (boolean, default false, partial index on
`(tenant_id) WHERE branch_only`).

| Event | Effect | Where |
|---|---|---|
| A finding is inserted with a branch that does not count | `branch_only = true` | `BEFORE INSERT` trigger `trg_findings_mark_branch_only` |
| A finding is inserted with no branch (host, cloud, pentest, manual…) or on a counting branch | `branch_only = false` | same trigger |
| A counting branch sees a branch-only finding (its occurrence there is recorded at ingest) | promoted: `branch_only = false`, `first_detected_at = now`, the SLA deadline keeps its length from now, `sla_status = on_track`; its workflows (notifications, ticket rules) run as for a new finding | `promote_branch_only_findings()` from `FindingProcessor.promoteBranchOnly` |
| A branch starts to count (made default, protected, retyped to `main`/`release`) | its branch-only findings are promoted (no workflows) | `AFTER UPDATE` trigger on `repository_branches` |
| No branch still shows a branch-only finding | `not_observed`, resolution `branch_expired`, a `status_changed` activity with reason `branch_only_expired` | `ExpireFeatureBranchFindings` (finding lifecycle job) |

Only the insert sets the mark: a finding that already counts is never hidden
later, and a branch that stops counting hides nothing. Each branch's own first
and last sighting stay in `finding_branch_occurrences`.

**Expiry.** An open branch-only finding (`new`, `open`, `confirmed`) expires
when the finding itself was not seen for the lifecycle job's default expiry
period and none of its occurrences is open and seen within its branch's
retention (`retention_days`, else the default). A deleted branch removes its
occurrences; a merged branch is no longer scanned, so its occurrences age out.
`keep_when_inactive` is not consulted: it keeps findings of branches that
count. `not_observed` is never a fix (owner decision O2); a sighting reopens
the finding without a regression flag.

## Where branch-only findings are left out

| Surface | How |
|---|---|
| Findings list, stats, groups, export, related CVEs (`GET /findings…`) | `vulnerability.WithBranchOnlyDefault` adds `branch_only = false` unless the request filters on `branch_only`, a branch (`branch_id`, `open_on_branch_id`, `fixed_on_branch_id`), a scan (`scan_id`) or ids (`id`). `branch_only=true` lists them. |
| SLA warning and breach escalation | `AND NOT f.branch_only` in both controller queries |
| Notifications and ticket rules on new findings | the created callback skips them (`FindingProcessor.withoutBranchOnly`); a promoted finding runs it then |
| Regression follow-up (fresh SLA, ticket comment, notification) | skipped for branch-only findings |
| Dashboards (stats, trend, MTTR, velocity, recent activity, data quality, process metrics), the executive summary and its top risks | `NOT branch_only` in `dashboard_repository.go` |
| Program metrics, CTEM cycle metrics, validation coverage by priority, findings by source | `NOT branch_only` in each query |
| Daily risk snapshots | `NOT branch_only` in `risk_snapshot.go` |
| Asset finding counts (inventory, `has_findings`, aggregate stats, graph), asset group and business unit counts, group findings | `NOT branch_only` in the asset, asset group and business unit repositories |
| Threat model status (findings on the model's assets) | `ListThreatFindings` |

Unchanged on purpose: the CI gate and the run page (they read the run's own
fingerprints), the branch pages and per-branch counts, a finding opened by
id, and the secret-to-credential bridge (a secret pushed to any branch of a
hosted repository is already exposed).

## Security

- Every query that reads or changes the mark is tenant-scoped
  (`tenant_id = $1` on `findings` and on `finding_branch_occurrences`); the
  branch trigger promotes per tenant of the branch's occurrences. Tests prove
  another tenant's promotion, lookup and expiry change nothing.
- The default can only narrow a list: it adds a predicate to the caller's
  compiled filter, which keeps the tenant, data-scope and pentest-membership
  predicates.
- A report cannot hide its findings by claiming a branch: the CI run's branch
  comes from the verified token (RFC-051), the default branch is never moved
  by a report (`maybeSetDefaultBranch`), and a repository with no known
  default branch hides nothing.
- A failed branch-only lookup notifies (fail open toward today's behaviour).

## Tests

- `internal/infra/postgres/finding_branch_only_db_test.go`: marking by branch
  kind, promotion (and its SLA restart) by a counting sighting and by branch
  reclassification, the default list, expiry with its activity, and the
  cross-tenant negatives.
- `internal/app/ingest/branch_only_test.go`: workflows skip branch-only
  findings and run for promoted ones.
- `pkg/domain/vulnerability/finding_branch_only_test.go`: the list default.
- `internal/infra/postgres/branch_only_metrics_db_test.go`: dashboards, the
  executive summary, recent activity, the threat model and asset counts leave
  a branch-only finding out, and count it once promoted.
