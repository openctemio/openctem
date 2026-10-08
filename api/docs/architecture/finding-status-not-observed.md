# Finding status `not_observed`

Research: `research/18-finding-to-vuln-lifecycle-and-fix-detection.md` (§6.2).
Owner decision O2 (2026-10-04).

The whole status set and lifecycle: [finding-status-lifecycle.md](finding-status-lifecycle.md).

## Meaning

`not_observed` means that recent scans no longer report the finding, **but
nothing proves the check ran against it** (no coverage proof). The finding is
stale, **not fixed**.

| Property | Value |
|---|---|
| Category | `in_progress` (open). Listed in `ActiveFindingStatuses`; never in `ClosedFindingStatuses`. |
| Counted as fixed | Never. It has no `resolved_at` and no `resolution_method`, so fix-rate and MTTR exclude it. |
| SLA | Keeps running: it is an open status. |
| Who sets it | Only the platform. No status transition leads to it, so `PATCH /findings/{id}/status`, bulk status and every other person-facing path refuse it. |
| Writers today | Feature-branch expiry (`ExpireFeatureBranchFindings`): a finding not seen on a non-default branch for the branch's retention period. `resolution = 'branch_expired'` records why. Branch-only expiry (same job): a branch-only finding no branch still shows (`branch-only-findings.md`). Coverage auto-resolve in enforce mode, for template drift: a covered nuclei run that did not report the finding but ran another template release (`templates_digest`) than the finding's last sighting (`MarkCoverageNotObserved`, research/18 O6). |
| Writers later | The closure evaluator (research 18 P2): a finding not reported by a run that could not prove coverage. |

## Leaving `not_observed`

| To | How |
|---|---|
| `confirmed` | A scan reports it again (`AutoReopenByFingerprintsBatch`; activity reason `observed_again`, **not** a regression), a retest still matches, or a person reopens it. |
| `in_progress` | A person picks it up. |
| `resolved` | A retest proves the fix (`retest_verified`), or a `findings:verify` holder closes it. Later also the closure evaluator with coverage proof. |
| `false_positive` / `accepted` | Through the approval workflow. |
| `duplicate` | Triage. |

## Storage

- Migration 000640 adds the `chk_findings_status` CHECK constraint. It names
  every status the API knows (plus the legacy `open`); before it, `findings.status` had no constraint.
- The migration moves rows closed by branch expiry (`status = 'resolved'`,
  `resolution = 'branch_expired'`) to `not_observed`, and clears `resolved_at`.
  Their provenance is certain, so no other row is touched.
- The regression trigger (`mark_finding_regression`) does not count
  `resolved → not_observed` or `resolved → accepted` as a regression.

## Web

- Label: "Not Observed".
- It belongs to the Findings list's "Open" status group (`FINDINGS_OPEN_STATUSES`)
  and to the grouped view's default statuses.
- It is a filter option on the repository findings tab.
- The status select never offers it as a target.
